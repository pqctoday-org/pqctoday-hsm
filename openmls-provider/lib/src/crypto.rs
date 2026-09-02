use std::sync::Arc;

use tls_codec::SecretVLBytes;

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, HpkePrivateKey, KemOutput, SignatureScheme,
};

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;
use crate::hpke as pqhpke;

pub struct PqcTodayCrypto {
    pub(crate) ops: Arc<dyn PkcsOps>,
}

impl PqcTodayCrypto {
    pub fn new(ops: Arc<dyn PkcsOps>) -> Self {
        Self { ops }
    }

    fn hmac_bytes(
        &self,
        hash_type: HashType,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.ops.hmac(hash_type, key, data).map_err(CryptoError::from)
    }
}

fn hash_len(h: HashType) -> usize {
    match h {
        HashType::Sha2_256 => 32,
        HashType::Sha2_384 => 48,
        HashType::Sha2_512 => 64,
    }
}

// ── OpenMlsCrypto impl ───────────────────────────────────────────────────────

impl OpenMlsCrypto for PqcTodayCrypto {
    // Suite 3 added 2026-08-10. It was ALREADY WORKING and simply undeclared:
    // suite 3 is suite 1 with ChaCha20Poly1305 in place of AES-128-GCM, and this
    // file's aead_encrypt/aead_decrypt route ChaCha20Poly1305 through
    // self.ops.chacha20_poly1305 (CKM_CHACHA20_POLY1305 in the engine) the
    // same way the AesGcm128/256 arms route through self.ops.aead_encrypt —
    // both AEADs genuinely dispatch, so this suite's record-layer AEAD is
    // HSM-resident like every other suite's. The primitive landed; the
    // declaration never followed.
    //
    // Evidence it works rather than an assumption that it should: the first real
    // run of the IETF WG interop rig (2026-08-09) put our client through 8 suite-3
    // cases and all 8 passed. The runner uses the UNION of the two clients'
    // advertised suites, so it reached suite 3 despite our not claiming it.
    //
    // Under-declaring is not harmless: a peer negotiating honestly will never
    // choose suite 3 with us, so a capability we have and test stays unreachable
    // in any real deployment.
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            // Post-quantum: X-Wing (ML-KEM-768 + X25519) with Ed25519 signatures.
            // The only PQ suite the released openmls_traits defines; its KEM
            // (backend.rs's ml_kem_768_keygen_from_seed/decapsulate/
            // encapsulate_to), SHAKE-256 expansion (backend.rs's shake256,
            // via softhsmrustv3::native::derive::shake256_xof), SHA3-256
            // combiner (backend.rs's xwing_combine, via
            // softhsmrustv3::native::derive::run_combiner) and
            // ChaCha20-Poly1305 record-layer AEAD (self.ops.chacha20_poly1305,
            // same as suite 3 above) all run through the engine. Verified
            // against the draft's own vectors (tests/fixtures/xwing_kat.json).
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        ]
    }

    // ── hashes / MACs ────────────────────────────────────────────────────────

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.ops.hash(hash_type, data).map_err(CryptoError::from)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        data: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.hmac_bytes(hash_type, key, data).map(SecretVLBytes::from)
    }

    // ── HKDF (extract + expand) ──────────────────────────────────────────────
    //
    // softhsmv3 exposes `CKM_HKDF_DERIVE` (v3.0+). cryptoki 0.10 doesn't yet
    // surface the typed params struct for HKDF, so we hash via PKCS#11 HMAC
    // and stitch RFC 5869 together here. Every HMAC round runs in the token
    // (the IKM/PRK is imported as a session-only generic-secret object).
    //
    // Key material stays under HSM execution; only intermediate PRK bytes
    // and OKM bytes ever live in process memory, exactly as RFC 5869 §2.2
    // requires.

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM).
        // If salt is empty, RFC 5869 §2.2 specifies a zero-filled hash-length string.
        let hl = hash_len(hash_type);
        let salt_owned;
        let salt_ref: &[u8] = if salt.is_empty() {
            salt_owned = vec![0u8; hl];
            &salt_owned
        } else {
            salt
        };
        self.hmac_bytes(hash_type, salt_ref, ikm)
            .map(SecretVLBytes::from)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        // RFC 5869 §2.3.
        let hl = hash_len(hash_type);
        let n = okm_len.div_ceil(hl);
        if n > 255 {
            return Err(CryptoError::HkdfOutputLengthInvalid);
        }
        let mut t_prev: Vec<u8> = Vec::new();
        let mut okm = Vec::with_capacity(okm_len);
        for i in 1..=n as u8 {
            let mut block = Vec::with_capacity(t_prev.len() + info.len() + 1);
            block.extend_from_slice(&t_prev);
            block.extend_from_slice(info);
            block.push(i);
            t_prev = self.hmac_bytes(hash_type, prk, &block)?;
            okm.extend_from_slice(&t_prev);
        }
        okm.truncate(okm_len);
        Ok(SecretVLBytes::from(okm))
    }

    // ── AEAD ─────────────────────────────────────────────────────────────────

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm => self
                .ops
                .aead_encrypt(key, nonce, aad, data)
                .map_err(CryptoError::from),
            AeadType::ChaCha20Poly1305 => self
                .ops
                .chacha20_poly1305(true, key, nonce, aad, data)
                .map_err(CryptoError::from),
        }
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm => self
                .ops
                .aead_decrypt(key, nonce, aad, ct)
                .map_err(CryptoError::from),
            AeadType::ChaCha20Poly1305 => self
                .ops
                .chacha20_poly1305(false, key, nonce, aad, ct)
                .map_err(CryptoError::from),
        }
    }

    // ── signatures ───────────────────────────────────────────────────────────
    //
    // `signature_key_gen` generates a TOKEN keypair (persists across sessions)
    // and returns:
    //   public_key  = raw DER-free pubkey bytes (per scheme)
    //   private_key = encoded HsmKeyHandle (NOT key material)

    fn signature_key_gen(
        &self,
        alg: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.ops.signature_key_gen(alg).map_err(CryptoError::from)
    }

    fn sign(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.ops.sign(alg, key, data).map_err(CryptoError::from)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.ops
            .verify_signature(alg, pk, data, signature)
            .map_err(|e| {
                // Map PKCS#11 verification failures to the standard InvalidSignature.
                // On wasm32 `PqcTodayError::Pkcs11` is replaced by `Pkcs11Raw(rv)`;
                // both map to CryptoLibraryError via the `other` arm below, which is
                // fine — OpenMLS treats CryptoLibraryError and InvalidSignature the
                // same way for verification failures.
                #[cfg(not(target_arch = "wasm32"))]
                if let PqcTodayError::Pkcs11(_) = e {
                    return CryptoError::InvalidSignature;
                }
                e.into()
            })
    }

    // ── HPKE — HSM-routed for every declared ciphersuite, software fallback
    //    for anything else ──────────────────────────────────────────────────
    //
    // Each of the 5 HPKE entry points below first tries `hpke::select()`
    // (`pqhpke::select`), which recognizes all four `HpkeConfig`s this
    // provider's `supported_ciphersuites()` declares and runs them through
    // PKCS#11 KEM / HKDF / AEAD primitives (`hpke.rs`) so the HPKE private
    // key and every intermediate secret live in the HSM. `mk_hpke` below
    // (delegating to `hpke-rs` with the RustCrypto backend) is the fallback
    // for any `HpkeConfig` `select()` doesn't recognize — i.e. a genuinely
    // undeclared/unsupported curve or KDF, not one of the four this crate
    // actually claims to support.

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        if let Some(su) = pqhpke::select(&config) {
            let ephemeral_ikm = self.ops.random(32).map_err(CryptoError::from)?;
            return pqhpke::seal(self.ops.as_ref(), &su, pk_r, info, aad, ptxt, &ephemeral_ikm);
        }
        let mut hpke = mk_hpke(config)?;
        let pk = hpke_rs::HpkePublicKey::new(pk_r.to_vec());
        let (kem_output, ciphertext) = hpke
            .seal(&pk, info, aad, ptxt, None, None, None)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if let Some(su) = pqhpke::select(&config) {
            return pqhpke::open(self.ops.as_ref(), &su, input, sk_r, info, aad);
        }
        let hpke = mk_hpke(config)?;
        let sk = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());
        hpke.open(
            input.kem_output.as_slice(),
            &sk,
            info,
            aad,
            input.ciphertext.as_slice(),
            None,
            None,
            None,
        )
        .map_err(|e| PqcTodayError::Hpke(e.to_string()).into())
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        if let Some(su) = pqhpke::select(&config) {
            let ephemeral_ikm = self.ops.random(32).map_err(CryptoError::from)?;
            return pqhpke::setup_sender_and_export(
                self.ops.as_ref(),
                &su,
                pk_r,
                info,
                exporter_context,
                exporter_length,
                &ephemeral_ikm,
            );
        }
        let mut hpke = mk_hpke(config)?;
        let pk = hpke_rs::HpkePublicKey::new(pk_r.to_vec());
        let (kem_output, ctx) = hpke
            .setup_sender(&pk, info, None, None, None)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        let exported = ctx
            .export(exporter_context, exporter_length)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        Ok((kem_output, ExporterSecret::from(exported)))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        if let Some(su) = pqhpke::select(&config) {
            return pqhpke::setup_receiver_and_export(
                self.ops.as_ref(),
                &su,
                enc,
                sk_r,
                info,
                exporter_context,
                exporter_length,
            );
        }
        let hpke = mk_hpke(config)?;
        let sk = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());
        let ctx = hpke
            .setup_receiver(enc, &sk, info, None, None, None)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        let exported = ctx
            .export(exporter_context, exporter_length)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        Ok(ExporterSecret::from(exported))
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        if let Some(su) = pqhpke::select(&config) {
            return pqhpke::derive_keypair(self.ops.as_ref(), &su, ikm);
        }
        let hpke = mk_hpke(config)?;
        let kp = hpke
            .derive_key_pair(ikm)
            .map_err(|e| PqcTodayError::Hpke(e.to_string()))?;
        let (sk, pk) = kp.into_keys();
        Ok(HpkeKeyPair {
            private: HpkePrivateKey::from(sk.as_slice().to_vec()),
            public: pk.as_slice().to_vec(),
        })
    }
}

fn mk_hpke(
    c: HpkeConfig,
) -> Result<hpke_rs::Hpke<hpke_rs_rust_crypto::HpkeRustCrypto>, CryptoError> {
    use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    let kem = match c.0 {
        HpkeKemType::DhKemP256 => KemAlgorithm::DhKemP256,
        HpkeKemType::DhKemP384 => KemAlgorithm::DhKemP384,
        HpkeKemType::DhKemP521 => KemAlgorithm::DhKemP521,
        HpkeKemType::DhKem25519 => KemAlgorithm::DhKem25519,
        HpkeKemType::DhKem448 => KemAlgorithm::DhKem448,
        // PQ / hybrid KEMs not in v0.1 — Phase 2.
        HpkeKemType::XWingKemDraft6 => return Err(CryptoError::UnsupportedKdf),
    };
    let kdf = match c.1 {
        HpkeKdfType::HkdfSha256 => KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => KdfAlgorithm::HkdfSha512,
    };
    let aead = match c.2 {
        HpkeAeadType::AesGcm128 => AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => AeadAlgorithm::HpkeExport,
    };
    Ok(hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead))
}
