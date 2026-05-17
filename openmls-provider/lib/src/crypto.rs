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
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
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
            AeadType::ChaCha20Poly1305 => sw_chacha20_encrypt(key, nonce, aad, data),
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
            AeadType::ChaCha20Poly1305 => sw_chacha20_decrypt(key, nonce, aad, ct),
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

    // ── HPKE — software fallback (Phase 1) ───────────────────────────────────
    //
    // The 5 HPKE entry points below delegate to `hpke-rs` with the
    // RustCrypto backend. Phase 2 will reroute these onto PKCS#11 KEM /
    // HKDF / AEAD primitives so HPKE keys can live in the HSM. See
    // README §Phase 2.

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        if pqhpke::supports_pkcs11_path(&config) {
            let ephemeral_ikm = self
                .ops
                .random(32)
                .map_err(PqcTodayError::from)
                .map_err(CryptoError::from)?;
            return pqhpke::seal(self.ops.as_ref(), pk_r, info, aad, ptxt, &ephemeral_ikm);
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
        if pqhpke::supports_pkcs11_path(&config) {
            return pqhpke::open(self.ops.as_ref(), input, sk_r, info, aad);
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
        if pqhpke::supports_pkcs11_path(&config) {
            let ephemeral_ikm = self
                .ops
                .random(32)
                .map_err(PqcTodayError::from)
                .map_err(CryptoError::from)?;
            return pqhpke::setup_sender_and_export(
                self.ops.as_ref(),
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
        if pqhpke::supports_pkcs11_path(&config) {
            return pqhpke::setup_receiver_and_export(
                self.ops.as_ref(),
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
        if pqhpke::supports_pkcs11_path(&config) {
            return pqhpke::derive_keypair(self.ops.as_ref(), ikm);
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

// ── Software AEAD for cipher suites the HSM doesn't expose ───────────────────
//
// ChaCha20-Poly1305 is used by MLS cipher suite 3. softhsmv3 exposes
// AES-GCM via CKM_AES_GCM; for ChaCha20 we fall back to RustCrypto's
// pure-software implementation which is constant-time on all platforms.

fn sw_chacha20_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::{aead::Aead, aead::KeyInit, aead::Payload, ChaCha20Poly1305, Nonce};
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = Nonce::from_slice(nonce);
    let ct = cipher
        .encrypt(nonce, Payload { msg: data, aad })
        .map_err(|_| CryptoError::HpkeEncryptionError)?;
    Ok(ct)
}

fn sw_chacha20_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::{aead::Aead, aead::KeyInit, aead::Payload, ChaCha20Poly1305, Nonce};
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CryptoError::HpkeDecryptionError)
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
