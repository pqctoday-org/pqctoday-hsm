//! `PkcsOps` trait — the PKCS#11 session abstraction seam.
//!
//! All HSM operations needed by `crypto.rs`, `hpke.rs`, `signer.rs`, and
//! `persistence.rs` are expressed as methods on this trait. The only
//! production implementation today is [`CryptokiBackend`] (native, wraps
//! [`HsmSession`]). A future `WasmPkcs11Backend` (wasm32, routes through
//! `softhsmrustv3` raw C_* FFI) will implement the same trait without
//! touching any of the calling code.
//!
//! ## Design choices
//!
//! * **No `cryptoki` types in the signature** — `Mechanism`, `Attribute`,
//!   `ObjectHandle` etc. are native-only types and cannot be expressed in a
//!   wasm32 build that doesn't have `cryptoki`. The trait methods are at a
//!   slightly higher level (e.g. `hmac(hash, key, data)` rather than
//!   `C_Sign(CKM_SHA256_HMAC, …)`).
//!
//! * **`Send + Sync`** — OpenMLS uses the provider from multiple threads.
//!   `CryptokiBackend` satisfies this because `HsmSession` already wraps the
//!   non-`Send` `Session` inside `Arc<Mutex<Session>>`.
//!
//! * **`SignatureKeyGenResult`** — signature key generation returns the raw
//!   public-key bytes AND a private-key descriptor (the opaque
//!   [`HsmKeyHandle`] blob on the native side). Bundled in a single call to
//!   keep the trait surface small.

use openmls_traits::types::{HashType, SignatureScheme};

use crate::error::PqcTodayError;

// ── helpers shared between CryptokiBackend methods ───────────────────────────
//
// These live here (not in crypto.rs) so CryptokiBackend can use them without
// creating a circular dependency between backend.rs ↔ crypto.rs.

#[cfg(not(target_arch = "wasm32"))]
mod native_helpers {
    use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, ObjectClass};
    use openmls_traits::types::{HashType, SignatureScheme};

    use crate::error::PqcTodayError;
    use crate::session::HsmSession;

    pub(super) fn hash_mech(h: HashType) -> Result<Mechanism<'static>, PqcTodayError> {
        match h {
            HashType::Sha2_256 => Ok(Mechanism::Sha256),
            HashType::Sha2_384 => Ok(Mechanism::Sha384),
            HashType::Sha2_512 => Ok(Mechanism::Sha512),
        }
    }

    pub(super) fn hmac_mech(h: HashType) -> Result<Mechanism<'static>, PqcTodayError> {
        match h {
            HashType::Sha2_256 => Ok(Mechanism::Sha256Hmac),
            HashType::Sha2_384 => Ok(Mechanism::Sha384Hmac),
            HashType::Sha2_512 => Ok(Mechanism::Sha512Hmac),
        }
    }

    pub(super) fn sig_mech(scheme: SignatureScheme) -> Result<Mechanism<'static>, PqcTodayError> {
        match scheme {
            SignatureScheme::ED25519 => {
                Ok(Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)))
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(Mechanism::EcdsaSha256),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(Mechanism::EcdsaSha384),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Ok(Mechanism::EcdsaSha512),
            other => Err(PqcTodayError::UnsupportedSignatureScheme(other)),
        }
    }

    /// Read `CKA_EC_POINT` on an **Edwards or Montgomery** public key.
    ///
    /// PKCS#11 v3.2 encodes this attribute differently per curve family. The
    /// Weierstrass table says *"DER-encoding of ANSI X9.62 ECPoint value Q"*;
    /// the Edwards and Montgomery tables say *"Public key bytes in little
    /// endian order as defined in [RFC 8032]"* — bare, unwrapped. The engines
    /// were DER-wrapping both until 2026-08-13 (C++ `OSSLEDPublicKey.cpp`
    /// E4 / Rust `ffi.rs`), which is what `unwrap_ec_point` below was written
    /// against; measured against the fixed C++ engine, an Ed25519 public key
    /// now reads back as **32 bare bytes** and `unwrap_ec_point` returned
    /// `MalformedKeyHandle`.
    ///
    /// The consumer was depending on non-conformant engine behaviour, so this
    /// reads the spec form first and keeps the DER form as a fallback so the
    /// provider still works against an older module. `expected` is the curve's
    /// defined public-key length, which is what disambiguates the two forms —
    /// a bare point carries no self-describing header.
    pub(super) fn unwrap_ec_point_bare(
        pt: &[u8],
        expected: usize,
    ) -> Result<Vec<u8>, PqcTodayError> {
        // v3.2 form: bare little-endian public key bytes.
        if pt.len() == expected {
            return Ok(pt.to_vec());
        }
        // Legacy form: DER OCTET STRING wrapper. Accept only if what comes
        // out is the right length — otherwise a bare point that happens to
        // start `04 <len>` would yield a short, silently wrong key.
        let inner = unwrap_ec_point(pt)?;
        if inner.len() == expected {
            return Ok(inner);
        }
        Err(PqcTodayError::MalformedKeyHandle)
    }

    /// PKCS#11 returns `CKA_EC_POINT` as a DER OCTET STRING wrapping the raw
    /// point bytes. RFC 9420 / MLS wants the raw bytes. Strip the wrapper.
    ///
    /// **Weierstrass curves only** — see `unwrap_ec_point_bare` for the
    /// Edwards/Montgomery encoding, which v3.2 defines as unwrapped.
    pub(super) fn unwrap_ec_point(der: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        if der.len() >= 2 && der[0] == 0x04 {
            let len = der[1] as usize;
            if len < 0x80 && der.len() == 2 + len {
                return Ok(der[2..2 + len].to_vec());
            }
            if der[1] == 0x81 && der.len() >= 3 {
                let len = der[2] as usize;
                if der.len() == 3 + len {
                    return Ok(der[3..3 + len].to_vec());
                }
            }
        }
        Err(PqcTodayError::MalformedKeyHandle)
    }

    /// Wrap raw EC point bytes in a DER OCTET STRING for PKCS#11
    /// `CKA_EC_POINT`.
    pub(super) fn wrap_ec_point(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len() + 3);
        out.push(0x04);
        if raw.len() < 0x80 {
            out.push(raw.len() as u8);
        } else {
            out.push(0x81);
            out.push(raw.len() as u8);
        }
        out.extend_from_slice(raw);
        out
    }

    /// Convert a raw P1363 ECDSA signature (r||s) to DER SEQUENCE {INTEGER r, INTEGER s}.
    /// PKCS#11 `CKM_ECDSA_*` returns P1363; OpenMLS/RustCrypto expects DER.
    pub(super) fn p1363_to_der(p1363: &[u8]) -> Result<Vec<u8>, crate::PqcTodayError> {
        let half = p1363.len() / 2;
        if half == 0 || p1363.len() != half * 2 {
            return Err(crate::PqcTodayError::MalformedKeyHandle);
        }
        let r = encode_der_integer(&p1363[..half]);
        let s = encode_der_integer(&p1363[half..]);
        let seq_body = r.len() + s.len();
        let mut out = Vec::with_capacity(2 + seq_body);
        out.push(0x30);
        if seq_body < 0x80 {
            out.push(seq_body as u8);
        } else {
            out.push(0x81);
            out.push(seq_body as u8);
        }
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        Ok(out)
    }

    /// Convert a DER-encoded ECDSA signature back to P1363 (r||s) for PKCS#11 verify.
    /// `coord_len` is the coordinate byte length (32 for P-256, 48 for P-384, 66 for P-521).
    pub(super) fn der_to_p1363(
        der: &[u8],
        coord_len: usize,
    ) -> Result<Vec<u8>, crate::PqcTodayError> {
        let err = crate::PqcTodayError::MalformedKeyHandle;
        if der.len() < 4 || der[0] != 0x30 {
            return Err(err);
        }
        let (body, offset) = if der[1] < 0x80 {
            (&der[2..2 + der[1] as usize], 2)
        } else if der[1] == 0x81 && der.len() >= 3 {
            (&der[3..3 + der[2] as usize], 3)
        } else {
            return Err(err);
        };
        let _ = offset;
        let (r_bytes, rest) = parse_der_integer(body)?;
        let (s_bytes, _) = parse_der_integer(rest)?;
        if r_bytes.len() > coord_len || s_bytes.len() > coord_len {
            return Err(err);
        }
        let mut out = vec![0u8; coord_len * 2];
        out[coord_len - r_bytes.len()..coord_len].copy_from_slice(r_bytes);
        out[coord_len * 2 - s_bytes.len()..].copy_from_slice(s_bytes);
        Ok(out)
    }

    fn encode_der_integer(raw: &[u8]) -> Vec<u8> {
        let stripped: Vec<u8> = raw.iter().copied().skip_while(|&b| b == 0).collect();
        let val = if stripped.is_empty() { vec![0u8] } else { stripped };
        let needs_pad = val[0] & 0x80 != 0;
        let content_len = val.len() + needs_pad as usize;
        let mut out = Vec::with_capacity(2 + content_len);
        out.push(0x02);
        out.push(content_len as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(&val);
        out
    }

    fn parse_der_integer(buf: &[u8]) -> Result<(&[u8], &[u8]), crate::PqcTodayError> {
        let err = crate::PqcTodayError::MalformedKeyHandle;
        if buf.len() < 2 || buf[0] != 0x02 {
            return Err(err);
        }
        let len = buf[1] as usize;
        if buf.len() < 2 + len {
            return Err(err);
        }
        let val = &buf[2..2 + len];
        // Strip mandatory leading 0x00 padding byte (positive integer marker)
        let val = if val.first() == Some(&0x00) && val.len() > 1 {
            &val[1..]
        } else {
            val
        };
        Ok((val, &buf[2 + len..]))
    }

    /// ECDSA coordinate length (bytes) for a given SignatureScheme.
    pub(super) fn ecdsa_coord_len(
        scheme: openmls_traits::types::SignatureScheme,
    ) -> Result<usize, crate::PqcTodayError> {
        use openmls_traits::types::SignatureScheme;
        match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(32),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(48),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Ok(66),
            other => Err(crate::PqcTodayError::UnsupportedSignatureScheme(other)),
        }
    }

    /// Find a private key object by `CKA_ID`.
    pub(super) fn find_priv_by_id(
        hsm: &HsmSession,
        cka_id: &[u8],
    ) -> Result<cryptoki::object::ObjectHandle, PqcTodayError> {
        hsm.with_session(|s| {
            let template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(cka_id.to_vec()),
            ];
            let mut found = s.find_objects(&template)?;
            found.pop().ok_or(PqcTodayError::ObjectNotFound)
        })
    }
}

// ── Public trait ─────────────────────────────────────────────────────────────

/// Abstraction over the PKCS#11 session surface used by this provider.
///
/// Implementations must be `Send + Sync` — OpenMLS uses the crypto/rand
/// providers from multiple threads.
pub trait PkcsOps: Send + Sync {
    // ── RNG ──────────────────────────────────────────────────────────────────

    /// Pull `n` random bytes from the hardware/software DRBG.
    fn random(&self, n: usize) -> Result<Vec<u8>, PqcTodayError>;

    // ── Hash / HMAC ───────────────────────────────────────────────────────────

    /// Run the PKCS#11 digest mechanism for `hash_type` over `data`.
    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, PqcTodayError>;

    /// Compute HMAC-<hash_type>(key, data). The key is a raw byte string;
    /// the implementation imports it as a session-only GENERIC_SECRET object.
    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError>;

    // ── AEAD ──────────────────────────────────────────────────────────────────

    /// AES-GCM encrypt (128 or 256 bit key). Returns ciphertext ‖ tag.
    fn aead_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError>;

    /// AES-GCM decrypt. `ct` is ciphertext ‖ tag.
    fn aead_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError>;

    // ── X25519 Diffie-Hellman (used by HPKE) ─────────────────────────────────

    // ── Operations `cryptoki` cannot express (served by softhsmrustv3) ──────
    //
    // Default to "unsupported" so a backend that has no route to them — the
    // wasm32 one — keeps compiling and fails loudly at the call site rather
    // than silently doing the work in software. Silent software fallback is
    // exactly how ChaCha20-Poly1305 stayed off the HSM for months.

    /// SHAKE-256 XOF, squeezing `out_len` bytes. Needed by X-Wing's seed
    /// expansion (draft-connolly-cfrg-xwing-kem §5.2/§5.6).
    fn shake256(&self, _input: &[u8], _out_len: usize) -> Result<Vec<u8>, PqcTodayError> {
        Err(PqcTodayError::Kem("SHAKE-256 not available on this backend".into()))
    }

    /// X-Wing combiner (draft-connolly-cfrg-xwing-kem §5.3):
    /// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`. There is no bare
    /// `sha3_256` method on this trait — a prior version had one, called
    /// directly from `hpke.rs` via the `sha3` crate with no engine
    /// involvement at all (no session, no mechanism dispatch), which is
    /// exactly the silent-software-fallback failure mode the comment just
    /// above this block warns about. This method exists instead so the
    /// transcript-build-then-hash recipe runs as a single named operation a
    /// real backend dispatches in full.
    fn xwing_combine(
        &self,
        _ss_m: &[u8],
        _ss_x: &[u8],
        _ct_x: &[u8],
        _pk_x: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        Err(PqcTodayError::Kem("X-Wing combiner not available on this backend".into()))
    }

    /// ChaCha20-Poly1305 AEAD. `encrypt` seals, otherwise opens.
    fn chacha20_poly1305(
        &self,
        _encrypt: bool,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        _input: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        Err(PqcTodayError::Kem("ChaCha20-Poly1305 not available on this backend".into()))
    }

    /// Deterministic ML-KEM-768 keygen from a 64-byte `d ‖ z` seed.
    /// Returns `(public_key_bytes, private_handle)`.
    fn ml_kem_768_keygen_from_seed(&self, _seed: &[u8]) -> Result<(Vec<u8>, u64), PqcTodayError> {
        Err(PqcTodayError::Kem("ML-KEM not available on this backend".into()))
    }

    /// ML-KEM decapsulation against a handle from
    /// [`Self::ml_kem_768_keygen_from_seed`].
    fn ml_kem_decapsulate(&self, _priv: u64, _ct: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        Err(PqcTodayError::Kem("ML-KEM not available on this backend".into()))
    }

    /// ML-KEM encapsulation against a raw encapsulation key.
    /// Returns `(ciphertext, shared_secret)`.
    fn ml_kem_encapsulate_to(&self, _pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        Err(PqcTodayError::Kem("ML-KEM not available on this backend".into()))
    }

    /// Compute a Diffie-Hellman shared secret via `CKM_ECDH1_DERIVE` (X25519).
    /// `sk` is the raw 32-byte private scalar; `peer_pk` is the raw 32-byte
    /// peer public key. Returns the raw 32-byte shared secret.
    fn ecdh_x25519(&self, sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, PqcTodayError>;

    // ── Signature keys ────────────────────────────────────────────────────────

    /// Generate a signing key pair for `scheme`.
    ///
    /// Returns `(pubkey_bytes, handle_blob)` where `pubkey_bytes` is the raw
    /// public key in the form OpenMLS expects (Ed25519: 32 B; P-256
    /// uncompressed: 65 B) and `handle_blob` is the opaque
    /// [`HsmKeyHandle`](crate::handle::HsmKeyHandle) encoding — NOT raw key
    /// material.
    fn signature_key_gen(
        &self,
        scheme: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError>;

    /// Sign `data` with the private key referenced by `handle_blob` (an
    /// [`HsmKeyHandle`](crate::handle::HsmKeyHandle) encoding).
    fn sign(
        &self,
        scheme: SignatureScheme,
        handle_blob: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError>;

    /// Verify `signature` over `data` against the raw public key `pk`.
    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        pk: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), PqcTodayError>;

    // ── Persistence (snapshot) ────────────────────────────────────────────────

    /// Store `data` as a durable `CKO_DATA` token object identified by
    /// `label`. If an object with that label already exists it is replaced.
    fn snapshot_write(&self, label: &str, data: &[u8]) -> Result<(), PqcTodayError>;

    /// Read the value of a `CKO_DATA` token object identified by `label`.
    /// Returns `None` if no such object exists.
    fn snapshot_read(&self, label: &str) -> Result<Option<Vec<u8>>, PqcTodayError>;
}

// ── CryptokiBackend (native) ─────────────────────────────────────────────────

/// Native implementation of [`PkcsOps`] backed by a live [`HsmSession`].
///
/// All PKCS#11 work runs inside the `Arc<Mutex<Session>>` guard in
/// `HsmSession::with_session`, which satisfies the `Send + Sync` requirement
/// even though `cryptoki::Session` is `!Send`.
#[cfg(not(target_arch = "wasm32"))]
pub struct CryptokiBackend {
    pub(crate) hsm: crate::session::HsmSession,
}

#[cfg(not(target_arch = "wasm32"))]
impl CryptokiBackend {
    pub fn new(hsm: crate::session::HsmSession) -> Self {
        Self { hsm }
    }

    /// Session on the **Rust** engine (`softhsmrustv3`), opened on first use.
    ///
    /// The post-quantum mechanisms — ML-KEM, SHA3-256, SHAKE-256,
    /// ChaCha20-Poly1305 — are unreachable through `cryptoki`, whose function
    /// list stops at PKCS#11 v3.0 and whose mechanism conversion is a closed
    /// allowlist. Rather than a second raw-FFI session onto the C++ module
    /// (which needed dlopen, hand-written marshalling and four workarounds, and
    /// crashed under parallelism), these run on the Rust engine linked in as an
    /// ordinary rlib. Its state is process-global behind a real Mutex, so a
    /// single shared session is correct.
    fn pq_session(&self) -> Result<u32, PqcTodayError> {
        // Copied out of the OnceLock; the handle is a u32.
        use softhsmrustv3::native::session;
        static SESSION: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
        SESSION
            .get_or_init(|| {
                session::init().ok()?;
                session::bootstrap_default_token(0, "so", "user", "pqctoday-mls").ok()
            })
            .as_ref()
            .copied()
            .ok_or_else(|| {
                PqcTodayError::Kem("could not open a softhsmrustv3 session".into())
            })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PkcsOps for CryptokiBackend {
    fn shake256(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>, PqcTodayError> {
        // softhsmrustv3::native::derive::shake256_xof — the engine's own
        // sha3::Shake256 usage (already present in its ffi.rs/handlers.rs
        // mu-gen path), exposed as a one-shot function. No session/handle
        // needed: unlike xwing_combine below, this isn't composed through
        // run_combiner (no CKM_SHAKE_256 digest-derivation codepoint exists
        // to route through — SHAKE-256 is a XOF, not a fixed-length digest),
        // but it is the engine's implementation, not a bare `sha3` crate
        // dependency of this crate's own.
        Ok(softhsmrustv3::native::derive::shake256_xof(input, out_len))
    }

    fn xwing_combine(
        &self,
        ss_m: &[u8],
        ss_x: &[u8],
        ct_x: &[u8],
        pk_x: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        // draft-connolly-cfrg-xwing-kem §5.3: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖
        // pk_X ‖ XWingLabel). Runs entirely through
        // softhsmrustv3::native::derive::run_combiner — the same
        // Combiner::Concat + FinalizeStep machinery KMIP's hybrid-KEM
        // combiners use, proven correct against this exact recipe by
        // rust/src/native/derive.rs's
        // run_combiner_xwing_sha3_256_recipe_matches_direct test. Every
        // intermediate handle (component secrets, the concatenated-then-
        // transcript-appended running secret) is destroyed inside
        // run_combiner before it returns; only the final combined secret
        // ever reaches this call site.
        use softhsmrustv3::constants::CKM_SHA3_256_KEY_DERIVATION;
        use softhsmrustv3::native::derive::{run_combiner, Combiner, FinalizeStep};

        let sess = self.pq_session()?;
        let mut transcript = Vec::with_capacity(ct_x.len() + pk_x.len() + crate::hpke::XWING_LABEL.len());
        transcript.extend_from_slice(ct_x);
        transcript.extend_from_slice(pk_x);
        transcript.extend_from_slice(&crate::hpke::XWING_LABEL);
        let combiner = Combiner::Concat {
            finalize: vec![
                FinalizeStep::ConcatData(transcript),
                FinalizeStep::Digest(CKM_SHA3_256_KEY_DERIVATION),
            ],
        };
        run_combiner(sess, &[ss_m, ss_x], &combiner)
            .map_err(|rv| PqcTodayError::Kem(format!("X-Wing combiner failed: 0x{rv:08x}")))
    }

    fn chacha20_poly1305(
        &self,
        encrypt: bool,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        // Reached via encrypt_with_key_bytes / decrypt_with_key_bytes, which are
        // public and take the key as raw bytes — exactly the shape HPKE has, so
        // no key object is needed. CKM_CHACHA20_POLY1305 = 0x4021.
        //
        // The earlier note here said this was unreachable because
        // chacha20_poly1305_encrypt is pub(crate). That was true of THAT
        // function and false of the operation: the public raw-key entry point
        // dispatches to it. Looking one level up found it.
        use softhsmrustv3::native::encrypt as enc;
        const CKM_CHACHA20_POLY1305: u32 = 0x0000_4021;
        let r = if encrypt {
            enc::encrypt_with_key_bytes(
                key, CKM_CHACHA20_POLY1305, input, Some(nonce), None, aad, None,
            )
        } else {
            enc::decrypt_with_key_bytes(
                key, CKM_CHACHA20_POLY1305, input, Some(nonce), None, aad, None,
            )
        };
        r.map_err(|rv| {
            PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 {} failed: 0x{rv:08x}",
                if encrypt { "encrypt" } else { "decrypt" }
            ))
        })
    }

    fn ml_kem_768_keygen_from_seed(&self, seed: &[u8]) -> Result<(Vec<u8>, u64), PqcTodayError> {
        use softhsmrustv3::native::keygen;
        let sess = self.pq_session()?;
        // CKP_ML_KEM_768 = 2. Extractable so the public key can be read back;
        // the private half never leaves the engine.
        let (h_pub, h_priv) = keygen::generate_ml_kem_keypair_from_seed_extractable(
            sess, 2, seed, b"mls-xwing", "mls-xwing",
        )
        .map_err(|rv| PqcTodayError::Kem(format!("ML-KEM keygen failed: 0x{rv:08x}")))?;
        let pk = softhsmrustv3::native::object::get_attribute(sess, h_pub, 0x0000_0011)
            .ok_or_else(|| PqcTodayError::Kem("ML-KEM public key has no CKA_VALUE".into()))?;
        Ok((pk, h_priv as u64))
    }

    fn ml_kem_decapsulate(&self, priv_handle: u64, ct: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        let sess = self.pq_session()?;
        softhsmrustv3::native::encrypt::decapsulate(sess, priv_handle as u32, 0x0000_0017, ct)
            .map_err(|rv| PqcTodayError::Kem(format!("ML-KEM decapsulate failed: 0x{rv:08x}")))
    }

    fn ml_kem_encapsulate_to(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        let sess = self.pq_session()?;
        // The engine already had the importer — keygen::register_ml_kem_public_key,
        // which validates the length against the parameter set (FIPS 203 Table 3)
        // rather than trusting it. I nearly re-wrote this from scratch because an
        // earlier grep was truncated and hid it.
        let h = softhsmrustv3::native::keygen::register_ml_kem_public_key(
            sess, 2, pk, b"mls-peer", "mls-peer",
        )
        .map_err(|rv| {
            PqcTodayError::Kem(format!("importing the peer ML-KEM key failed: 0x{rv:08x}"))
        })?;
        softhsmrustv3::native::encrypt::encapsulate(sess, h, 0x0000_0017)
            .map_err(|rv| PqcTodayError::Kem(format!("ML-KEM encapsulate failed: 0x{rv:08x}")))
    }

    fn random(&self, n: usize) -> Result<Vec<u8>, PqcTodayError> {
        self.hsm
            .with_session(|s| Ok(s.generate_random_vec(n as u32)?))
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        let mech = native_helpers::hash_mech(hash_type)?;
        self.hsm.with_session(|s| Ok(s.digest(&mech, data)?))
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        use cryptoki::object::{Attribute, KeyType, ObjectClass};
        let mech = native_helpers::hmac_mech(hash_type)?;
        self.hsm.with_session(|s| {
            let key_obj = s.create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::Sign(true),
                Attribute::Value(key.to_vec()),
            ])?;
            let sig = s.sign(&mech, key_obj, data)?;
            let _ = s.destroy_object(key_obj);
            Ok(sig)
        })
    }

    fn aead_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, KeyType, ObjectClass};
        let mut nonce_buf = nonce.to_vec();
        let params =
            cryptoki::mechanism::aead::GcmParams::new(&mut nonce_buf, aad, 128.into())?;
        let mech = Mechanism::AesGcm(params);
        self.hsm.with_session(|s| {
            let key_obj = s.create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::Encrypt(true),
                Attribute::Value(key.to_vec()),
            ])?;
            let ct = s.encrypt(&mech, key_obj, pt)?;
            let _ = s.destroy_object(key_obj);
            Ok(ct)
        })
    }

    fn aead_decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, KeyType, ObjectClass};
        let mut nonce_buf = nonce.to_vec();
        let params =
            cryptoki::mechanism::aead::GcmParams::new(&mut nonce_buf, aad, 128.into())?;
        let mech = Mechanism::AesGcm(params);
        self.hsm.with_session(|s| {
            let key_obj = s.create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::Decrypt(true),
                Attribute::Value(key.to_vec()),
            ])?;
            let pt = s.decrypt(&mech, key_obj, ct)?;
            let _ = s.destroy_object(key_obj);
            Ok(pt)
        })
    }

    fn ecdh_x25519(&self, sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
        use cryptoki::types::Ulong;

        const X25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x6e];
        const NSECRET: usize = 32;

        self.hsm.with_session(|s| {
            let sk_obj = s.create_object(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(false),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::Derive(true),
                Attribute::EcParams(X25519_OID.to_vec()),
                Attribute::Value(sk.to_vec()),
            ])?;
            let params = Ecdh1DeriveParams::new(EcKdf::null(), peer_pk);
            let mech = Mechanism::Ecdh1Derive(params);
            let derived = s.derive_key(
                &mech,
                sk_obj,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::ValueLen(Ulong::from(NSECRET as u64)),
                ],
            )?;
            let attrs = s.get_attributes(derived, &[AttributeType::Value])?;
            let _ = s.destroy_object(derived);
            let _ = s.destroy_object(sk_obj);
            for a in attrs {
                if let Attribute::Value(v) = a {
                    return Ok(v);
                }
            }
            Err(PqcTodayError::ObjectNotFound)
        })
    }

    fn signature_key_gen(
        &self,
        scheme: SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        use cryptoki::mechanism::Mechanism;
        use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};

        use crate::handle::HsmKeyHandle;

        // Mint a fresh CKA_ID from the HSM RNG.
        let cka_id = self.random(16)?;

        // The 4th element is the RFC 8032 public-key length for curve families
        // whose `CKA_EC_POINT` PKCS#11 v3.2 defines as BARE (Edwards /
        // Montgomery); `None` means the Weierstrass DER `ECPoint` encoding,
        // which v3.2 leaves wrapped.
        let (gen_mech, pub_tmpl, priv_tmpl, bare_point_len) = match scheme {
            SignatureScheme::ED25519 => (
                Mechanism::EccEdwardsKeyPairGen,
                vec![
                    Attribute::Class(ObjectClass::PUBLIC_KEY),
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(cka_id.clone()),
                    Attribute::EcParams(vec![0x06, 0x03, 0x2b, 0x65, 0x70]),
                ],
                vec![
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::Token(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                    Attribute::Id(cka_id.clone()),
                ],
                Some(32),
            ),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => (
                Mechanism::EccKeyPairGen,
                vec![
                    Attribute::Class(ObjectClass::PUBLIC_KEY),
                    Attribute::KeyType(KeyType::EC),
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::Id(cka_id.clone()),
                    Attribute::EcParams(vec![
                        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                    ]),
                ],
                vec![
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(KeyType::EC),
                    Attribute::Token(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                    Attribute::Id(cka_id.clone()),
                ],
                None,
            ),
            other => return Err(PqcTodayError::UnsupportedSignatureScheme(other)),
        };

        let (pub_handle, _priv_handle) = self
            .hsm
            .with_session(|s| Ok(s.generate_key_pair(&gen_mech, &pub_tmpl, &priv_tmpl)?))?;

        let pub_bytes = self.hsm.with_session(|s| {
            let attrs = s.get_attributes(pub_handle, &[AttributeType::EcPoint])?;
            for a in attrs {
                if let Attribute::EcPoint(pt) = a {
                    return match bare_point_len {
                        Some(n) => native_helpers::unwrap_ec_point_bare(&pt, n),
                        None => native_helpers::unwrap_ec_point(&pt),
                    };
                }
            }
            Err(PqcTodayError::ObjectNotFound)
        })?;

        let handle = HsmKeyHandle {
            cka_id,
            scheme: scheme as u16,
        };
        Ok((pub_bytes, handle.encode()))
    }

    fn sign(
        &self,
        scheme: SignatureScheme,
        handle_blob: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        use crate::handle::HsmKeyHandle;

        let handle = HsmKeyHandle::decode(handle_blob)?;
        if handle.scheme != scheme as u16 {
            return Err(PqcTodayError::UnsupportedSignatureScheme(scheme));
        }
        let priv_obj = native_helpers::find_priv_by_id(&self.hsm, &handle.cka_id)?;
        let mech = native_helpers::sig_mech(scheme)?;
        let raw_sig = self
            .hsm
            .with_session(|s| Ok(s.sign(&mech, priv_obj, data)?))?;
        // PKCS#11 CKM_ECDSA_* returns P1363 (r||s); OpenMLS expects DER.
        match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256
            | SignatureScheme::ECDSA_SECP384R1_SHA384
            | SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                native_helpers::p1363_to_der(&raw_sig)
            }
            _ => Ok(raw_sig),
        }
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        pk: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), PqcTodayError> {
        use cryptoki::object::{Attribute, KeyType, ObjectClass};

        let mech = native_helpers::sig_mech(scheme)?;
        // OpenMLS passes DER-encoded ECDSA signatures; PKCS#11 CKM_ECDSA_*
        // expects P1363. Convert before handing off to the HSM.
        let sig_for_hsm: Vec<u8>;
        let signature = match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256
            | SignatureScheme::ECDSA_SECP384R1_SHA384
            | SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let coord = native_helpers::ecdsa_coord_len(scheme)?;
                sig_for_hsm = native_helpers::der_to_p1363(signature, coord)?;
                sig_for_hsm.as_slice()
            }
            _ => signature,
        };
        let (key_type, ec_params): (KeyType, Vec<u8>) = match scheme {
            SignatureScheme::ED25519 => {
                (KeyType::EC_EDWARDS, vec![0x06, 0x03, 0x2b, 0x65, 0x70])
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => (
                KeyType::EC,
                vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            ),
            other => return Err(PqcTodayError::UnsupportedSignatureScheme(other)),
        };
        let ec_point_der = native_helpers::wrap_ec_point(pk);
        self.hsm.with_session(|s| {
            let pub_obj = s.create_object(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(key_type),
                Attribute::Token(false),
                Attribute::Verify(true),
                Attribute::EcParams(ec_params),
                Attribute::EcPoint(ec_point_der),
            ])?;
            let r = s.verify(&mech, pub_obj, data, signature);
            let _ = s.destroy_object(pub_obj);
            r.map_err(PqcTodayError::from)
        })
    }

    fn snapshot_write(&self, label: &str, data: &[u8]) -> Result<(), PqcTodayError> {
        use cryptoki::object::{Attribute, ObjectClass};

        // Find and destroy any existing object with this label.
        let existing = self.hsm.with_session(|s| {
            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            Ok(s.find_objects(&template)?.first().copied())
        })?;
        if let Some(handle) = existing {
            self.hsm.with_session(|s| {
                s.destroy_object(handle)?;
                Ok(())
            })?;
        }
        // Create the new object.
        self.hsm.with_session(|s| {
            s.create_object(&[
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Value(data.to_vec()),
            ])?;
            Ok(())
        })
    }

    fn snapshot_read(&self, label: &str) -> Result<Option<Vec<u8>>, PqcTodayError> {
        use cryptoki::object::{Attribute, AttributeType, ObjectClass};

        let handle = self.hsm.with_session(|s| {
            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            Ok(s.find_objects(&template)?.first().copied())
        })?;
        let handle = match handle {
            Some(h) => h,
            None => return Ok(None),
        };
        self.hsm.with_session(|s| {
            let attrs = s.get_attributes(handle, &[AttributeType::Value])?;
            for a in attrs {
                if let Attribute::Value(v) = a {
                    return Ok(Some(v));
                }
            }
            Err(PqcTodayError::ObjectNotFound)
        })
    }
}

// ── Send + Sync for CryptokiBackend ──────────────────────────────────────────
//
// `cryptoki::Session` is `!Send`; the `Arc<Mutex<Session>>` inside
// `HsmSession` provides the required synchronisation.  We assert the impl
// explicitly so the compiler catches any future regression.
#[cfg(not(target_arch = "wasm32"))]
unsafe impl Send for CryptokiBackend {}
#[cfg(not(target_arch = "wasm32"))]
unsafe impl Sync for CryptokiBackend {}

// ── WasmPkcs11Backend ────────────────────────────────────────────────────────
//
// wasm32 implementation of `PkcsOps`. Routes every operation through the
// `softhsmrustv3` in-process PKCS#11 engine via its raw `C_*` FFI entry
// points — the same calling convention proven in `wasm-smoke/src/lib.rs`.
//
// Design: stateless struct, opens a fresh session per operation.
// softhsmrustv3 handles many concurrent sessions without issue.

#[cfg(target_arch = "wasm32")]
mod wasm_backend {
    use openmls_traits::types::{HashType, SignatureScheme};

    use softhsmrustv3::ffi::{
        C_CreateObject, C_DestroyObject, C_Digest, C_DigestInit,
        C_EncryptMessage, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit, C_GenerateKeyPair,
        C_GenerateRandom, C_GetAttributeValue, C_Initialize, C_MessageDecryptInit,
        C_MessageEncryptInit, C_OpenSession, C_Sign, C_SignInit, C_Verify, C_VerifyInit,
    };
    use softhsmrustv3::constants::{
        CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT,
        CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_SIGN, CKA_TOKEN, CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY,
        CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_AES, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY,
        CKK_GENERIC_SECRET, CKM_AES_GCM, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_DERIVE, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
        CKM_EDDSA, CKM_SHA256, CKM_SHA256_HMAC, CKM_SHA384, CKM_SHA384_HMAC, CKM_SHA512,
        CKM_SHA512_HMAC, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKR_OK,
    };

    use crate::error::PqcTodayError;
    use crate::handle::HsmKeyHandle;

    // ── Standard PKCS#11 constants not exported by softhsmrustv3::constants ──

    /// CKA_LABEL — PKCS#11 v3.2 §4.3 (standard value 0x00000003).
    const CKA_LABEL: u32 = 0x0000_0003;
    /// CKA_ID — PKCS#11 v3.2 §4.5 (standard value 0x00000102).
    const CKA_ID: u32 = 0x0000_0102;
    /// CKO_DATA — PKCS#11 v3.2 §4.2 (standard value 0x00000000).
    const CKO_DATA: u32 = 0x0000_0000;
    /// CKD_NULL — KDF identifier "no key derivation" (standard value 0x00000001).
    const CKD_NULL: u32 = 0x0000_0001;
    /// X25519 OID: 1.3.101.110 → 06 03 2b 65 6e
    const X25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x6e];
    /// Ed25519 OID: 1.3.101.112 → 06 03 2b 65 70
    const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    /// P-256 OID: 1.2.840.10045.3.1.7 → 06 08 2a 86 48 ce 3d 03 01 07
    const P256_OID: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    // ── Attribute-template helpers ────────────────────────────────────────────

    /// Write a 4-byte LE u32 into `buf` and return a pointer to it.
    #[inline(always)]
    fn u32_attr(buf: &mut [u8; 4], val: u32) -> *const u8 {
        buf.copy_from_slice(&val.to_le_bytes());
        buf.as_ptr()
    }

    /// Write a 1-byte boolean into `buf` and return a pointer to it.
    #[inline(always)]
    fn bool_attr(buf: &mut u8, val: bool) -> *const u8 {
        *buf = if val { 1 } else { 0 };
        buf as *const u8
    }

    // ── PKCS#11 session helpers ───────────────────────────────────────────────

    /// Call `C_Initialize` idempotently. Returns an error if the RV is
    /// neither `CKR_OK` nor `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191).
    fn pkcs11_init_idempotent() -> Result<(), PqcTodayError> {
        let rv = C_Initialize(std::ptr::null_mut());
        if rv == CKR_OK || rv == 0x191 {
            Ok(())
        } else {
            Err(PqcTodayError::Pkcs11Raw(rv))
        }
    }

    /// Open a RW session against slot 0. Returns the session handle.
    fn pkcs11_open_session() -> Result<u32, PqcTodayError> {
        let mut h_sess: u32 = 0;
        let rv = C_OpenSession(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut h_sess as *mut u32,
        );
        if rv == CKR_OK {
            Ok(h_sess)
        } else {
            Err(PqcTodayError::Pkcs11Raw(rv))
        }
    }

    /// `pkcs11_init_idempotent()` + `pkcs11_open_session()` in one call.
    fn open() -> Result<u32, PqcTodayError> {
        pkcs11_init_idempotent()?;
        pkcs11_open_session()
    }

    // ── Mechanism helpers ─────────────────────────────────────────────────────

    fn hash_mech_id(h: HashType) -> u32 {
        match h {
            HashType::Sha2_256 => CKM_SHA256,
            HashType::Sha2_384 => CKM_SHA384,
            HashType::Sha2_512 => CKM_SHA512,
        }
    }

    fn hmac_mech_id(h: HashType) -> u32 {
        match h {
            HashType::Sha2_256 => CKM_SHA256_HMAC,
            HashType::Sha2_384 => CKM_SHA384_HMAC,
            HashType::Sha2_512 => CKM_SHA512_HMAC,
        }
    }

    fn hash_output_len(h: HashType) -> usize {
        match h {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
        }
    }

    fn sig_mech_id(scheme: SignatureScheme) -> Result<u32, PqcTodayError> {
        match scheme {
            SignatureScheme::ED25519 => Ok(CKM_EDDSA),
            SignatureScheme::ECDSA_SECP256R1_SHA256 => Ok(CKM_ECDSA_SHA256),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => Ok(CKM_ECDSA_SHA384),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Ok(CKM_ECDSA_SHA512),
            other => Err(PqcTodayError::UnsupportedSignatureScheme(other)),
        }
    }

    /// Maximum output bytes for a DER-encoded ECDSA signature (P-256 = 72 B max).
    fn ecdsa_sig_buf_len(scheme: SignatureScheme) -> usize {
        match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => 72,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => 104,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => 139,
            _ => 72,
        }
    }

    // ── FindObjects helper ────────────────────────────────────────────────────

    /// Run C_FindObjectsInit → C_FindObjects → C_FindObjectsFinal.
    /// Returns up to `max_results` matching object handles.
    fn find_objects(h_sess: u32, tmpl: &mut [u32]) -> Result<Vec<u32>, PqcTodayError> {
        let n_attrs = (tmpl.len() / 3) as u32;
        let rv = C_FindObjectsInit(h_sess, tmpl.as_mut_ptr() as *mut u8, n_attrs);
        if rv != CKR_OK {
            return Err(PqcTodayError::Pkcs11Raw(rv));
        }
        let mut handles = vec![0u32; 16];
        let mut count: u32 = 0;
        let rv = C_FindObjects(h_sess, handles.as_mut_ptr(), handles.len() as u32, &mut count);
        C_FindObjectsFinal(h_sess);
        if rv != CKR_OK {
            return Err(PqcTodayError::Pkcs11Raw(rv));
        }
        handles.truncate(count as usize);
        Ok(handles)
    }

    /// Two-pass C_GetAttributeValue: size query then read.
    /// Returns the raw bytes for the single attribute at index 0 of a 1-attr template.
    fn get_single_attr(h_sess: u32, h_obj: u32, attr_type: u32) -> Result<Vec<u8>, PqcTodayError> {
        // First pass: null ptr → populates length
        let mut tmpl: [u32; 3] = [attr_type, 0, 0];
        C_GetAttributeValue(h_sess, h_obj, tmpl.as_mut_ptr() as *mut u8, 1);
        let len = tmpl[2] as usize;
        if len == 0 || len == 0xFFFF_FFFF as usize {
            return Err(PqcTodayError::ObjectNotFound);
        }
        // Second pass: read into buffer
        let mut buf = vec![0u8; len];
        let mut tmpl2: [u32; 3] = [attr_type, buf.as_mut_ptr() as u32, len as u32];
        let rv = C_GetAttributeValue(h_sess, h_obj, tmpl2.as_mut_ptr() as *mut u8, 1);
        if rv != CKR_OK {
            return Err(PqcTodayError::Pkcs11Raw(rv));
        }
        Ok(buf)
    }

    // ── Wrap/unwrap EC point (same logic as native_helpers) ───────────────────

    /// Strip DER OCTET STRING wrapper from `CKA_EC_POINT` bytes.
    fn unwrap_ec_point(der: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        if der.len() >= 2 && der[0] == 0x04 {
            let len = der[1] as usize;
            if len < 0x80 && der.len() == 2 + len {
                return Ok(der[2..2 + len].to_vec());
            }
            if der[1] == 0x81 && der.len() >= 3 {
                let len = der[2] as usize;
                if der.len() == 3 + len {
                    return Ok(der[3..3 + len].to_vec());
                }
            }
        }
        Err(PqcTodayError::MalformedKeyHandle)
    }

    /// Wrap raw EC point bytes in DER OCTET STRING for `CKA_EC_POINT`.
    fn wrap_ec_point(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len() + 3);
        out.push(0x04);
        if raw.len() < 0x80 {
            out.push(raw.len() as u8);
        } else {
            out.push(0x81);
            out.push(raw.len() as u8);
        }
        out.extend_from_slice(raw);
        out
    }

    // ── WasmPkcs11Backend struct and PkcsOps impl ─────────────────────────────

    /// wasm32 `PkcsOps` implementation backed by `softhsmrustv3` in-process.
    ///
    /// Stateless — opens a fresh session per operation via `C_OpenSession`.
    pub struct WasmPkcs11Backend;

    // On wasm32 there is no real multithreading; these impls are safe.
    unsafe impl Send for WasmPkcs11Backend {}
    unsafe impl Sync for WasmPkcs11Backend {}

    impl super::PkcsOps for WasmPkcs11Backend {
        // ── RNG ──────────────────────────────────────────────────────────────

        fn random(&self, n: usize) -> Result<Vec<u8>, PqcTodayError> {
            let h_sess = open()?;
            let mut buf = vec![0u8; n];
            let rv = C_GenerateRandom(h_sess, buf.as_mut_ptr(), n as u32);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            Ok(buf)
        }

        // ── Hash ─────────────────────────────────────────────────────────────

        fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
            let h_sess = open()?;
            let mech_id = hash_mech_id(hash_type);
            // CK_MECHANISM: [mech_type(u32), pParam(u32)=null, ulParamLen(u32)=0]
            // For parameter-less mechanisms we pass only the first 4 bytes (mech_type).
            let mut mech: [u8; 4] = mech_id.to_ne_bytes();
            let rv = C_DigestInit(h_sess, mech.as_mut_ptr());
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            let out_len = hash_output_len(hash_type);
            let mut digest = vec![0u8; out_len];
            let mut digest_len = out_len as u32;
            let rv = C_Digest(
                h_sess,
                data.as_ptr() as *mut u8,
                data.len() as u32,
                digest.as_mut_ptr(),
                &mut digest_len,
            );
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            digest.truncate(digest_len as usize);
            Ok(digest)
        }

        // ── HMAC ─────────────────────────────────────────────────────────────

        fn hmac(
            &self,
            hash_type: HashType,
            key: &[u8],
            data: &[u8],
        ) -> Result<Vec<u8>, PqcTodayError> {
            let h_sess = open()?;

            // Import key as session CKO_SECRET_KEY / CKK_GENERIC_SECRET with CKA_SIGN=true.
            let mut class_buf = [0u8; 4];
            let mut ktype_buf = [0u8; 4];
            let mut sign_buf: u8 = 0;
            let mut token_buf: u8 = 0;
            let class_ptr = u32_attr(&mut class_buf, CKO_SECRET_KEY);
            let ktype_ptr = u32_attr(&mut ktype_buf, CKK_GENERIC_SECRET);
            let sign_ptr = bool_attr(&mut sign_buf, true);
            let token_ptr = bool_attr(&mut token_buf, false);

            #[rustfmt::skip]
            let mut tmpl: [u32; 15] = [
                CKA_CLASS,    class_ptr as u32, 4,
                CKA_KEY_TYPE, ktype_ptr as u32, 4,
                CKA_VALUE,    key.as_ptr() as u32, key.len() as u32,
                CKA_SIGN,     sign_ptr as u32, 1,
                CKA_TOKEN,    token_ptr as u32, 1,
            ];

            let mut h_key: u32 = 0;
            let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 5, &mut h_key);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let mech_id = hmac_mech_id(hash_type);
            let mut mech: [u32; 3] = [mech_id, 0, 0];
            let rv = C_SignInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
            if rv != CKR_OK {
                C_DestroyObject(h_sess, h_key);
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let out_len = hash_output_len(hash_type);
            let mut mac = vec![0u8; out_len];
            let mut mac_len = out_len as u32;
            let rv = C_Sign(
                h_sess,
                data.as_ptr() as *mut u8,
                data.len() as u32,
                mac.as_mut_ptr(),
                &mut mac_len,
            );
            C_DestroyObject(h_sess, h_key);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            mac.truncate(mac_len as usize);
            Ok(mac)
        }

        // ── AEAD encrypt ─────────────────────────────────────────────────────
        //
        // Uses C_MessageEncryptInit + C_EncryptMessage to support AAD.
        // The softhsmrustv3 C_Encrypt path ignores AAD; the MessageEncrypt
        // path passes AAD directly to the aes-gcm Payload.
        //
        // Output format: ciphertext ‖ 16-byte GCM tag (same as the native
        // CryptokiBackend and the C_Encrypt no-AAD path).

        fn aead_encrypt(
            &self,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            pt: &[u8],
        ) -> Result<Vec<u8>, PqcTodayError> {
            let h_sess = open()?;
            let h_key = create_aes_key_obj(h_sess, key, true, false)?;

            // C_MessageEncryptInit: just the AES-GCM mechanism type (no params needed here).
            let mut mech: [u32; 3] = [CKM_AES_GCM, 0, 0];
            let rv = C_MessageEncryptInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
            if rv != CKR_OK {
                C_DestroyObject(h_sess, h_key);
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            // CK_GCM_MESSAGE_PARAMS (wasm32, 6 × u32 = 24 bytes):
            //   [0] pIv:         *mut u8   — pointer to IV buffer (must be writable for iv_gen)
            //   [1] ulIvLen:     u32       — 12
            //   [2] ulIvFixedBits: u32     — 0
            //   [3] ulIvGen:     u32       — 0 (caller provides IV; 1 = softhsm generates it)
            //   [4] pTag:        *mut u8   — pointer to 16-byte tag output buffer
            //   [5] ulTagBits:   u32       — 128
            let mut nonce_buf: Vec<u8> = nonce.to_vec();
            let mut tag_buf = vec![0u8; 16];
            let mut gcm_msg_params: [u32; 6] = [
                nonce_buf.as_mut_ptr() as u32,
                nonce_buf.len() as u32,
                0,
                0,
                tag_buf.as_mut_ptr() as u32,
                128,
            ];

            // Output: exactly pt.len() bytes (tag is written separately to p_tag).
            let mut ct = vec![0u8; pt.len()];
            let mut ct_len = pt.len() as u32;

            let rv = C_EncryptMessage(
                h_sess,
                gcm_msg_params.as_mut_ptr() as *mut u8,
                24, // sizeof(CK_GCM_MESSAGE_PARAMS) on wasm32
                if aad.is_empty() {
                    std::ptr::null()
                } else {
                    aad.as_ptr()
                },
                aad.len() as u32,
                pt.as_ptr(),
                pt.len() as u32,
                ct.as_mut_ptr(),
                &mut ct_len,
            );
            C_DestroyObject(h_sess, h_key);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            ct.truncate(ct_len as usize);
            // Append 16-byte GCM tag to match the C_Encrypt output contract.
            ct.extend_from_slice(&tag_buf);
            Ok(ct)
        }

        // ── AEAD decrypt ─────────────────────────────────────────────────────
        //
        // `ct` is ciphertext ‖ 16-byte GCM tag. We split off the tag and
        // pass it separately via the pTag pointer in CK_GCM_MESSAGE_PARAMS.

        fn aead_decrypt(
            &self,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ct: &[u8],
        ) -> Result<Vec<u8>, PqcTodayError> {
            const TAG_LEN: usize = 16;
            if ct.len() < TAG_LEN {
                return Err(PqcTodayError::Pkcs11Raw(0x0000_0040)); // CKR_ENCRYPTED_DATA_INVALID
            }
            let ciphertext = &ct[..ct.len() - TAG_LEN];
            let tag_bytes = &ct[ct.len() - TAG_LEN..];

            let h_sess = open()?;
            let h_key = create_aes_key_obj(h_sess, key, false, true)?;

            let mut mech: [u32; 3] = [CKM_AES_GCM, 0, 0];
            let rv = C_MessageDecryptInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
            if rv != CKR_OK {
                C_DestroyObject(h_sess, h_key);
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let mut nonce_buf: Vec<u8> = nonce.to_vec();
            let mut tag_buf: Vec<u8> = tag_bytes.to_vec();
            let mut gcm_msg_params: [u32; 6] = [
                nonce_buf.as_mut_ptr() as u32,
                nonce_buf.len() as u32,
                0,
                0,
                tag_buf.as_mut_ptr() as u32,
                128,
            ];

            let mut pt = vec![0u8; ciphertext.len()];
            let mut pt_len = ciphertext.len() as u32;

            use softhsmrustv3::ffi::C_DecryptMessage;
            let rv = C_DecryptMessage(
                h_sess,
                gcm_msg_params.as_mut_ptr() as *mut u8,
                24,
                if aad.is_empty() {
                    std::ptr::null()
                } else {
                    aad.as_ptr()
                },
                aad.len() as u32,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                pt.as_mut_ptr(),
                &mut pt_len,
            );
            C_DestroyObject(h_sess, h_key);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            pt.truncate(pt_len as usize);
            Ok(pt)
        }

        // ── ECDH X25519 ───────────────────────────────────────────────────────
        //
        // Import `sk` as CKO_PRIVATE_KEY / CKK_EC_MONTGOMERY with CKA_DERIVE=true.
        // Derive via CKM_EC_MONTGOMERY_KEY_DERIVE.
        // Read CKA_VALUE off the derived key.

        fn ecdh_x25519(&self, sk: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
            const NSECRET: usize = 32;
            let h_sess = open()?;

            // Import private scalar.
            let mut class_buf = [0u8; 4];
            let mut ktype_buf = [0u8; 4];
            let mut derive_buf: u8 = 0;
            let mut token_buf: u8 = 0;
            let mut ext_buf: u8 = 0;
            let mut no_sign_buf: u8 = 0;
            let class_ptr = u32_attr(&mut class_buf, CKO_PRIVATE_KEY);
            let ktype_ptr = u32_attr(&mut ktype_buf, CKK_EC_MONTGOMERY);
            let derive_ptr = bool_attr(&mut derive_buf, true);
            let token_ptr = bool_attr(&mut token_buf, false);
            let ext_ptr = bool_attr(&mut ext_buf, true);
            let no_sign_ptr = bool_attr(&mut no_sign_buf, false);

            #[rustfmt::skip]
            let mut sk_tmpl: [u32; 24] = [
                CKA_CLASS,       class_ptr as u32,               4,
                CKA_KEY_TYPE,    ktype_ptr as u32,               4,
                CKA_VALUE,       sk.as_ptr() as u32,             sk.len() as u32,
                CKA_DERIVE,      derive_ptr as u32,              1,
                CKA_TOKEN,       token_ptr as u32,               1,
                CKA_EC_PARAMS,   X25519_OID.as_ptr() as u32,     X25519_OID.len() as u32,
                CKA_EXTRACTABLE, ext_ptr as u32,                 1,
                CKA_SIGN,        no_sign_ptr as u32,             1,
            ];

            let mut h_sk: u32 = 0;
            let rv = C_CreateObject(h_sess, sk_tmpl.as_mut_ptr() as *mut u8, 8, &mut h_sk);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            // CK_ECDH1_DERIVE_PARAMS (wasm32, 5 × u32 = 20 bytes):
            //   [0] kdf:              u32  = CKD_NULL (1)
            //   [1] ulSharedDataLen:  u32  = 0
            //   [2] pSharedData:      u32  = null
            //   [3] ulPublicDataLen:  u32  = peer_pk.len()
            //   [4] pPublicData:      u32  = peer_pk.as_ptr()
            let ecdh_params: [u32; 5] = [
                CKD_NULL,
                0,
                0,
                peer_pk.len() as u32,
                peer_pk.as_ptr() as u32,
            ];
            let mut mech: [u32; 3] = [
                CKM_EC_MONTGOMERY_KEY_DERIVE,
                ecdh_params.as_ptr() as u32,
                20,
            ];

            // Derived key template: CKO_SECRET_KEY, CKK_GENERIC_SECRET, extractable, 32 B.
            let mut d_class_buf = [0u8; 4];
            let mut d_ktype_buf = [0u8; 4];
            let mut d_vlen_buf = [0u8; 4];
            let mut d_ext_buf: u8 = 0;
            let mut d_token_buf: u8 = 0;
            let d_class_ptr = u32_attr(&mut d_class_buf, CKO_SECRET_KEY);
            let d_ktype_ptr = u32_attr(&mut d_ktype_buf, CKK_GENERIC_SECRET);
            let d_vlen_ptr = u32_attr(&mut d_vlen_buf, NSECRET as u32);
            let d_ext_ptr = bool_attr(&mut d_ext_buf, true);
            let d_token_ptr = bool_attr(&mut d_token_buf, false);

            #[rustfmt::skip]
            let mut der_tmpl: [u32; 15] = [
                CKA_CLASS,       d_class_ptr as u32, 4,
                CKA_KEY_TYPE,    d_ktype_ptr as u32, 4,
                CKA_VALUE_LEN,   d_vlen_ptr as u32,  4,
                CKA_EXTRACTABLE, d_ext_ptr as u32,   1,
                CKA_TOKEN,       d_token_ptr as u32, 1,
            ];

            let mut h_derived: u32 = 0;
            use softhsmrustv3::ffi::C_DeriveKey;
            let rv = C_DeriveKey(
                h_sess,
                mech.as_mut_ptr() as *mut u8,
                h_sk,
                der_tmpl.as_mut_ptr() as *mut u8,
                5,
                &mut h_derived,
            );
            C_DestroyObject(h_sess, h_sk);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let secret = get_single_attr(h_sess, h_derived, CKA_VALUE)?;
            C_DestroyObject(h_sess, h_derived);
            Ok(secret)
        }

        // ── Signature key gen ─────────────────────────────────────────────────
        //
        // Generate a TOKEN keypair, return (pubkey_bytes, HsmKeyHandle blob).
        // Public key: Ed25519 → CKA_VALUE (32 B); P-256 → CKA_EC_POINT (DER → strip).

        fn signature_key_gen(
            &self,
            scheme: SignatureScheme,
        ) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
            let h_sess = open()?;

            // Mint a 16-byte random CKA_ID.
            let cka_id = self.random(16)?;

            let (mech_id, pub_bytes) = match scheme {
                SignatureScheme::ED25519 => {
                    // PKCS#11 v3.2 §6.3.10 — the Edwards curves "can only be
                    // specified in the CKA_EC_PARAMS attribute of the template
                    // for the public key using the curveName or the oID
                    // methods". The engine used to ignore the attribute and
                    // hardcode Ed25519 (so an Ed448 request silently returned
                    // an Ed25519 key); since the W2 fix it reads CKA_EC_PARAMS
                    // from the public template, falls back to the private, and
                    // returns CKR_TEMPLATE_INCOMPLETE when neither carries it.
                    // The comment that used to sit here — "no template attrs
                    // needed beyond CKA_TOKEN + CKA_ID" — described the
                    // non-conformant behaviour, not the specification. The
                    // P-256 arm below always supplied its curve OID and was
                    // never affected.
                    let mut mech: [u32; 3] = [CKM_EC_EDWARDS_KEY_PAIR_GEN, 0, 0];

                    // Public key template: CKA_TOKEN, CKA_VERIFY, CKA_ID,
                    // CKA_EC_PARAMS = id-Ed25519.
                    let mut pub_token_buf: u8 = 0;
                    let mut pub_verify_buf: u8 = 0;
                    let pub_token_ptr = bool_attr(&mut pub_token_buf, true);
                    let pub_verify_ptr = bool_attr(&mut pub_verify_buf, true);
                    #[rustfmt::skip]
                    let mut pub_tmpl: [u32; 12] = [
                        CKA_TOKEN,     pub_token_ptr as u32,          1,
                        CKA_VERIFY,    pub_verify_ptr as u32,         1,
                        CKA_ID,        cka_id.as_ptr() as u32,        cka_id.len() as u32,
                        CKA_EC_PARAMS, ED25519_OID.as_ptr() as u32,   ED25519_OID.len() as u32,
                    ];
                    // Private key template: CKA_TOKEN=true, CKA_SIGN=true, CKA_ID=cka_id
                    let mut prv_token_buf: u8 = 0;
                    let mut prv_sign_buf: u8 = 0;
                    let prv_token_ptr = bool_attr(&mut prv_token_buf, true);
                    let prv_sign_ptr = bool_attr(&mut prv_sign_buf, true);
                    #[rustfmt::skip]
                    let mut prv_tmpl: [u32; 9] = [
                        CKA_TOKEN, prv_token_ptr as u32,    1,
                        CKA_SIGN,  prv_sign_ptr as u32,     1,
                        CKA_ID,    cka_id.as_ptr() as u32,  cka_id.len() as u32,
                    ];

                    let mut h_pub: u32 = 0;
                    let mut h_priv: u32 = 0;
                    let rv = C_GenerateKeyPair(
                        h_sess,
                        mech.as_mut_ptr() as *mut u8,
                        pub_tmpl.as_mut_ptr() as *mut u8,
                        4,
                        prv_tmpl.as_mut_ptr() as *mut u8,
                        3,
                        &mut h_pub,
                        &mut h_priv,
                    );
                    if rv != CKR_OK {
                        return Err(PqcTodayError::Pkcs11Raw(rv));
                    }
                    // PKCS#11 v3.2's Edwards public-key table: "Public key
                    // bytes in little endian order as defined in [RFC 8032]",
                    // in CKA_EC_POINT — bare, NOT DER-wrapped (that wording is
                    // deliberately different from the Weierstrass table's
                    // "DER-encoding of ANSI X9.62 ECPoint value Q"), and there
                    // is no CKA_VALUE on a public key at all. This used to read
                    // CKA_VALUE, which the E4 fix deleted for Edwards and
                    // Montgomery public keys; the old comment ("raw 32 B in
                    // CKA_VALUE") documented the engine's non-conformant
                    // layout. No unwrapping: the bytes are already raw.
                    let raw = get_single_attr(h_sess, h_pub, CKA_EC_POINT)?;
                    // Tolerate an older module that still DER-wraps this to 34
                    // bytes, but only when the unwrapped result is the right
                    // length — never hand MLS a short key. Mirrors
                    // `native_helpers::unwrap_ec_point_bare` on the native path.
                    let pub_bytes = if raw.len() == 32 {
                        raw
                    } else {
                        let inner = unwrap_ec_point(&raw)?;
                        if inner.len() != 32 {
                            return Err(PqcTodayError::MalformedKeyHandle);
                        }
                        inner
                    };
                    (scheme, pub_bytes)
                }

                SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                    let mut mech: [u32; 3] = [CKM_EC_KEY_PAIR_GEN, 0, 0];

                    let mut pub_token_buf: u8 = 0;
                    let mut pub_verify_buf: u8 = 0;
                    let pub_token_ptr = bool_attr(&mut pub_token_buf, true);
                    let pub_verify_ptr = bool_attr(&mut pub_verify_buf, true);
                    #[rustfmt::skip]
                    let mut pub_tmpl: [u32; 12] = [
                        CKA_TOKEN,     pub_token_ptr as u32,          1,
                        CKA_VERIFY,    pub_verify_ptr as u32,         1,
                        CKA_EC_PARAMS, P256_OID.as_ptr() as u32,      P256_OID.len() as u32,
                        CKA_ID,        cka_id.as_ptr() as u32,        cka_id.len() as u32,
                    ];
                    let mut prv_token_buf: u8 = 0;
                    let mut prv_sign_buf: u8 = 0;
                    let prv_token_ptr = bool_attr(&mut prv_token_buf, true);
                    let prv_sign_ptr = bool_attr(&mut prv_sign_buf, true);
                    #[rustfmt::skip]
                    let mut prv_tmpl: [u32; 9] = [
                        CKA_TOKEN, prv_token_ptr as u32,    1,
                        CKA_SIGN,  prv_sign_ptr as u32,     1,
                        CKA_ID,    cka_id.as_ptr() as u32,  cka_id.len() as u32,
                    ];

                    let mut h_pub: u32 = 0;
                    let mut h_priv: u32 = 0;
                    let rv = C_GenerateKeyPair(
                        h_sess,
                        mech.as_mut_ptr() as *mut u8,
                        pub_tmpl.as_mut_ptr() as *mut u8,
                        4,
                        prv_tmpl.as_mut_ptr() as *mut u8,
                        3,
                        &mut h_pub,
                        &mut h_priv,
                    );
                    if rv != CKR_OK {
                        return Err(PqcTodayError::Pkcs11Raw(rv));
                    }
                    // P-256 public key: CKA_EC_POINT returns DER OCTET STRING; strip it.
                    let ec_point_der = get_single_attr(h_sess, h_pub, CKA_EC_POINT)?;
                    let pub_bytes = unwrap_ec_point(&ec_point_der)?;
                    (scheme, pub_bytes)
                }

                other => return Err(PqcTodayError::UnsupportedSignatureScheme(other)),
            };

            let handle = HsmKeyHandle { cka_id, scheme: mech_id as u16 };
            Ok((pub_bytes, handle.encode()))
        }

        // ── Sign ──────────────────────────────────────────────────────────────
        //
        // Decode HsmKeyHandle → CKA_ID → C_FindObjects → h_priv → C_Sign.

        fn sign(
            &self,
            scheme: SignatureScheme,
            handle_blob: &[u8],
            data: &[u8],
        ) -> Result<Vec<u8>, PqcTodayError> {
            let handle = HsmKeyHandle::decode(handle_blob)?;
            if handle.scheme != scheme as u16 {
                return Err(PqcTodayError::UnsupportedSignatureScheme(scheme));
            }
            let cka_id = &handle.cka_id;
            let h_sess = open()?;

            // Find private key by CKA_ID + CKA_CLASS=CKO_PRIVATE_KEY.
            let mut class_buf = [0u8; 4];
            let class_ptr = u32_attr(&mut class_buf, CKO_PRIVATE_KEY);
            #[rustfmt::skip]
            let mut find_tmpl: [u32; 6] = [
                CKA_CLASS, class_ptr as u32,             4,
                CKA_ID,    cka_id.as_ptr() as u32,       cka_id.len() as u32,
            ];
            let found = find_objects(h_sess, &mut find_tmpl)?;
            let h_priv = *found.first().ok_or(PqcTodayError::ObjectNotFound)?;

            let mech_id = sig_mech_id(scheme)?;
            let mut mech: [u32; 3] = [mech_id, 0, 0];
            let rv = C_SignInit(h_sess, mech.as_mut_ptr() as *mut u8, h_priv);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let sig_buf_len = match scheme {
                SignatureScheme::ED25519 => 64,
                _ => ecdsa_sig_buf_len(scheme),
            };
            let mut sig = vec![0u8; sig_buf_len];
            let mut sig_len = sig_buf_len as u32;
            let rv = C_Sign(
                h_sess,
                data.as_ptr() as *mut u8,
                data.len() as u32,
                sig.as_mut_ptr(),
                &mut sig_len,
            );
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            sig.truncate(sig_len as usize);
            Ok(sig)
        }

        // ── Verify signature ──────────────────────────────────────────────────
        //
        // Create a session public-key object, run C_VerifyInit + C_Verify,
        // then destroy the ephemeral key object.

        fn verify_signature(
            &self,
            scheme: SignatureScheme,
            pk: &[u8],
            data: &[u8],
            signature: &[u8],
        ) -> Result<(), PqcTodayError> {
            let h_sess = open()?;
            let mech_id = sig_mech_id(scheme)?;

            let h_pub = match scheme {
                SignatureScheme::ED25519 => {
                    // Ed25519: CKO_PUBLIC_KEY / CKK_EC_EDWARDS, CKA_VALUE = raw 32 B.
                    let mut class_buf = [0u8; 4];
                    let mut ktype_buf = [0u8; 4];
                    let mut verify_buf: u8 = 0;
                    let mut token_buf: u8 = 0;
                    let class_ptr = u32_attr(&mut class_buf, CKO_PUBLIC_KEY);
                    let ktype_ptr = u32_attr(&mut ktype_buf, CKK_EC_EDWARDS);
                    let verify_ptr = bool_attr(&mut verify_buf, true);
                    let token_ptr = bool_attr(&mut token_buf, false);
                    #[rustfmt::skip]
                    let mut tmpl: [u32; 18] = [
                        CKA_CLASS,     class_ptr as u32,               4,
                        CKA_KEY_TYPE,  ktype_ptr as u32,               4,
                        CKA_VALUE,     pk.as_ptr() as u32,             pk.len() as u32,
                        CKA_VERIFY,    verify_ptr as u32,              1,
                        CKA_TOKEN,     token_ptr as u32,               1,
                        CKA_EC_PARAMS, ED25519_OID.as_ptr() as u32,    ED25519_OID.len() as u32,
                    ];
                    let mut h_pub: u32 = 0;
                    let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 6, &mut h_pub);
                    if rv != CKR_OK {
                        return Err(PqcTodayError::Pkcs11Raw(rv));
                    }
                    h_pub
                }

                SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                    // ECDSA P-256: CKO_PUBLIC_KEY / CKK_EC, CKA_EC_PARAMS = P-256 OID,
                    // CKA_EC_POINT = DER OCTET STRING wrapping uncompressed point.
                    let ec_point_der = wrap_ec_point(pk);
                    let mut class_buf = [0u8; 4];
                    let mut ktype_buf = [0u8; 4];
                    let mut verify_buf: u8 = 0;
                    let mut token_buf: u8 = 0;
                    let class_ptr = u32_attr(&mut class_buf, CKO_PUBLIC_KEY);
                    let ktype_ptr = u32_attr(&mut ktype_buf, CKK_EC);
                    let verify_ptr = bool_attr(&mut verify_buf, true);
                    let token_ptr = bool_attr(&mut token_buf, false);
                    #[rustfmt::skip]
                    let mut tmpl: [u32; 18] = [
                        CKA_CLASS,     class_ptr as u32,                   4,
                        CKA_KEY_TYPE,  ktype_ptr as u32,                   4,
                        CKA_EC_PARAMS, P256_OID.as_ptr() as u32,           P256_OID.len() as u32,
                        CKA_EC_POINT,  ec_point_der.as_ptr() as u32,       ec_point_der.len() as u32,
                        CKA_VERIFY,    verify_ptr as u32,                  1,
                        CKA_TOKEN,     token_ptr as u32,                   1,
                    ];
                    let mut h_pub: u32 = 0;
                    let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 6, &mut h_pub);
                    if rv != CKR_OK {
                        return Err(PqcTodayError::Pkcs11Raw(rv));
                    }
                    h_pub
                }

                other => return Err(PqcTodayError::UnsupportedSignatureScheme(other)),
            };

            let mut mech: [u32; 3] = [mech_id, 0, 0];
            let rv = C_VerifyInit(h_sess, mech.as_mut_ptr() as *mut u8, h_pub);
            if rv != CKR_OK {
                C_DestroyObject(h_sess, h_pub);
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }

            let rv = C_Verify(
                h_sess,
                data.as_ptr() as *mut u8,
                data.len() as u32,
                signature.as_ptr() as *mut u8,
                signature.len() as u32,
            );
            C_DestroyObject(h_sess, h_pub);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            Ok(())
        }

        // ── Snapshot write ────────────────────────────────────────────────────
        //
        // Store `data` as a durable CKO_DATA token object keyed by `label`.
        // If an existing object with this label exists, destroy it first.

        fn snapshot_write(&self, label: &str, data: &[u8]) -> Result<(), PqcTodayError> {
            let h_sess = open()?;
            let label_bytes = label.as_bytes();

            // Find and destroy existing object with this label.
            let existing = {
                let mut class_buf = [0u8; 4];
                let class_ptr = u32_attr(&mut class_buf, CKO_DATA);
                #[rustfmt::skip]
                let mut find_tmpl: [u32; 6] = [
                    CKA_CLASS, class_ptr as u32,               4,
                    CKA_LABEL, label_bytes.as_ptr() as u32,    label_bytes.len() as u32,
                ];
                find_objects(h_sess, &mut find_tmpl)?
            };
            for h in existing {
                C_DestroyObject(h_sess, h);
            }

            // Create the new CKO_DATA token object.
            let mut class_buf = [0u8; 4];
            let mut token_buf: u8 = 0;
            let class_ptr = u32_attr(&mut class_buf, CKO_DATA);
            let token_ptr = bool_attr(&mut token_buf, true); // CKA_TOKEN=true → persists
            #[rustfmt::skip]
            let mut create_tmpl: [u32; 15] = [
                CKA_CLASS, class_ptr as u32,               4,
                CKA_LABEL, label_bytes.as_ptr() as u32,    label_bytes.len() as u32,
                CKA_VALUE, data.as_ptr() as u32,           data.len() as u32,
                CKA_TOKEN, token_ptr as u32,               1,
                0,         0,                              0, // pad to multiple-of-3
            ];
            let mut h_obj: u32 = 0;
            let rv = C_CreateObject(h_sess, create_tmpl.as_mut_ptr() as *mut u8, 4, &mut h_obj);
            if rv != CKR_OK {
                return Err(PqcTodayError::Pkcs11Raw(rv));
            }
            Ok(())
        }

        // ── Snapshot read ─────────────────────────────────────────────────────

        fn snapshot_read(&self, label: &str) -> Result<Option<Vec<u8>>, PqcTodayError> {
            let h_sess = open()?;
            let label_bytes = label.as_bytes();

            let mut class_buf = [0u8; 4];
            let class_ptr = u32_attr(&mut class_buf, CKO_DATA);
            #[rustfmt::skip]
            let mut find_tmpl: [u32; 6] = [
                CKA_CLASS, class_ptr as u32,               4,
                CKA_LABEL, label_bytes.as_ptr() as u32,    label_bytes.len() as u32,
            ];
            let found = find_objects(h_sess, &mut find_tmpl)?;
            let h_obj = match found.first() {
                Some(&h) => h,
                None => return Ok(None),
            };
            let val = get_single_attr(h_sess, h_obj, CKA_VALUE)?;
            Ok(Some(val))
        }
    }

    // ── AES key object helper ─────────────────────────────────────────────────

    /// Create a session CKO_SECRET_KEY / CKK_AES object with the given key bytes.
    /// `can_encrypt` and `can_decrypt` control the CKA_ENCRYPT/CKA_DECRYPT flags.
    fn create_aes_key_obj(
        h_sess: u32,
        key: &[u8],
        can_encrypt: bool,
        can_decrypt: bool,
    ) -> Result<u32, PqcTodayError> {
        let mut class_buf = [0u8; 4];
        let mut ktype_buf = [0u8; 4];
        let mut enc_buf: u8 = 0;
        let mut dec_buf: u8 = 0;
        let mut token_buf: u8 = 0;
        let mut ext_buf: u8 = 0;
        let class_ptr = u32_attr(&mut class_buf, CKO_SECRET_KEY);
        let ktype_ptr = u32_attr(&mut ktype_buf, CKK_AES);
        let enc_ptr = bool_attr(&mut enc_buf, can_encrypt);
        let dec_ptr = bool_attr(&mut dec_buf, can_decrypt);
        let token_ptr = bool_attr(&mut token_buf, false);
        let ext_ptr = bool_attr(&mut ext_buf, true);

        #[rustfmt::skip]
        let mut tmpl: [u32; 21] = [
            CKA_CLASS,       class_ptr as u32, 4,
            CKA_KEY_TYPE,    ktype_ptr as u32, 4,
            CKA_VALUE,       key.as_ptr() as u32, key.len() as u32,
            CKA_ENCRYPT,     enc_ptr as u32,   1,
            CKA_DECRYPT,     dec_ptr as u32,   1,
            CKA_TOKEN,       token_ptr as u32, 1,
            CKA_EXTRACTABLE, ext_ptr as u32,   1,
        ];

        let mut h_key: u32 = 0;
        let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 7, &mut h_key);
        if rv != CKR_OK {
            return Err(PqcTodayError::Pkcs11Raw(rv));
        }
        Ok(h_key)
    }
} // mod wasm_backend

#[cfg(target_arch = "wasm32")]
pub use wasm_backend::WasmPkcs11Backend;
