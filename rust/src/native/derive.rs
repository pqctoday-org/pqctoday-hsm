//! Key derivation — typed wrappers over the engine's `C_DeriveKey` mechanisms
//! (the `native::*` counterpart to the FFI derive path, per the module-level
//! typed-vs-FFI architectural relationship in [`super`]).
//!
//! These exist so the KMIP layer can compose a hybrid-KEM shared secret
//! entirely in-HSM without any crypto crate of its own: it calls
//! [`concatenate_keys`] (and, as the combiner set grows, the digest/HKDF
//! derive wrappers) against key *handles*, and only the final combined secret
//! is ever released. Private component keys never leave the engine.
//!
//! Every function here maps 1:1 to a standard PKCS#11 v3.2 derive mechanism,
//! so a combiner built from them is conformant by construction — PKCS#11 v3.2
//! has no dedicated hybrid-KEM mechanism (verified against the published
//! spec), only these composable building blocks.

use std::collections::HashMap;

use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::state::{
    allocate_handle_owned, compute_kcv, get_object_value, store_bool, store_ulong,
};

/// Register a freshly-derived generic-secret key `value` as a session object
/// and return its handle. Mirrors the FFI `C_DeriveKey` finalization
/// (`ffi.rs`): the derived key is extractable/non-sensitive (it IS the
/// caller's requested output — e.g. a KEM shared secret meant to be read),
/// not locally generated (`CKA_LOCAL = false`,
/// `CKA_KEY_GEN_MECHANISM = UNAVAILABLE`), and carries a KCV per PKCS#11 v3.2
/// §4.11.
fn register_derived_secret(session: u32, value: Vec<u8>) -> u32 {
    let mut attrs: Attributes = HashMap::new();
    let vlen = value.len() as u32;
    attrs.insert(CKA_VALUE, value);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    store_ulong(&mut attrs, CKA_VALUE_LEN, vlen);
    store_bool(&mut attrs, CKA_EXTRACTABLE, true);
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    // PKCS#11 v3.2 §4.3 Table 13 — a DERIVED key is not locally generated.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    // §4.9/§4.10 — derived-from-external-material ⇒ never ALWAYS_SENSITIVE /
    // NEVER_EXTRACTABLE.
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    allocate_handle_owned(session, attrs)
}

/// `CKM_CONCATENATE_BASE_AND_KEY` (PKCS#11 v3.2 §6.43.3): derive a new
/// generic-secret key whose value is `base.CKA_VALUE ‖ second.CKA_VALUE`.
///
/// This is the universal step-1 building block for every hybrid-KEM combiner
/// (the classical ‖ PQC concatenation); a hash/KDF second step, when a
/// combiner needs one, chains another `native::` derive wrapper onto the
/// handle this returns. All in-HSM — the two component secrets are addressed
/// by handle and only the combined result is produced.
///
/// Returns `CKR_KEY_HANDLE_INVALID` if either handle has no readable value.
///
/// **Pre-condition**: `session` must be a valid R/W user session; both
/// handles must reference secret-key objects with a `CKA_VALUE`.
pub fn concatenate_keys(session: u32, base: u32, second: u32) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let second_val = get_object_value(second).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let combined = [base_val.as_slice(), second_val.as_slice()].concat();
    Ok(register_derived_secret(session, combined))
}

/// `CKM_CONCATENATE_BASE_AND_DATA` (PKCS#11 v3.2 §6.43.4): derive a new
/// generic-secret key whose value is `base.CKA_VALUE ‖ data`.
///
/// The transcript-binding building block — appends non-key material
/// (ciphertext, public key, domain-separation label) onto a running secret
/// before a hash step, as constructions like X-Wing and Chempat require.
///
/// **Pre-condition**: `session` valid R/W; `base` a secret key with a value.
pub fn concatenate_data(session: u32, base: u32, data: &[u8]) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let combined = [base_val.as_slice(), data].concat();
    Ok(register_derived_secret(session, combined))
}

/// Digest key-derivation (PKCS#11 v3.2 §6.22 SHA-2 / §6.29 SHA-3): derive a
/// new generic-secret key whose value is `SHAx(base.CKA_VALUE)`, left-
/// truncated to `out_len` bytes when supplied (`None` keeps the full digest).
///
/// The hash-second-step for concat-then-hash combiners (SSH
/// `mlkem768x25519-sha256`: SHA-256 of `ss_mlkem ‖ ss_x25519`, verified from
/// the OpenSSH source; X-Wing: SHA3-256 of `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label`,
/// verified from draft-connolly-cfrg-xwing-kem). `mech` selects the digest;
/// any non-digest-derivation mechanism → `CKR_MECHANISM_INVALID`.
/// The base key's value is read in-HSM and never leaves.
///
/// **Pre-condition**: `session` valid R/W; `base` a secret key with a value.
pub fn digest_key_derivation(
    session: u32,
    base: u32,
    mech: u32,
    out_len: Option<usize>,
) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let mut digest = digest_of(mech, &base_val)?;
    if let Some(n) = out_len {
        if n > digest.len() {
            // Can't stretch a digest — §6.22: the requested key is longer than
            // the hash provides.
            return Err(CKR_KEY_SIZE_RANGE);
        }
        digest.truncate(n); // §6.22 — leftmost bytes.
    }
    Ok(register_derived_secret(session, digest))
}

/// Pure digest-key-derivation transform: `SHAx(data)` per `mech` (one of the
/// `CKM_SHA*_KEY_DERIVATION` codepoints). Shared by [`digest_key_derivation`]
/// (native) and the `C_DeriveKey` FFI arm so the mechanism→hasher mapping
/// exists once. `CKR_MECHANISM_INVALID` for any non-digest-derivation mech.
pub(crate) fn digest_of(mech: u32, data: &[u8]) -> Result<Vec<u8>, CkRv> {
    use sha2::Digest as _;
    Ok(match mech {
        CKM_SHA256_KEY_DERIVATION => sha2::Sha256::digest(data).to_vec(),
        CKM_SHA384_KEY_DERIVATION => sha2::Sha384::digest(data).to_vec(),
        CKM_SHA512_KEY_DERIVATION => sha2::Sha512::digest(data).to_vec(),
        CKM_SHA3_256_KEY_DERIVATION => sha3::Sha3_256::digest(data).to_vec(),
        CKM_SHA3_384_KEY_DERIVATION => sha3::Sha3_384::digest(data).to_vec(),
        CKM_SHA3_512_KEY_DERIVATION => sha3::Sha3_512::digest(data).to_vec(),
        _ => return Err(CKR_MECHANISM_INVALID),
    })
}

/// HKDF (RFC 5869) over the PRF selected by `prf` — `Extract(salt, ikm)` then
/// `Expand(info)` to `len` bytes. Mirrors the `hkdf` crate usage in the FFI
/// `C_DeriveKey` HKDF arm (`ffi.rs`) so the mechanism→hasher mapping is
/// identical: `prf` ∈ {`CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512`,
/// `CKM_SHA3_256`, `CKM_SHA3_512`} (SHA-256 default). `salt = None` uses the
/// all-zero salt per RFC 5869 §2.2. All bytes stay in the engine.
pub(crate) fn hkdf_extract_expand(
    prf: u32,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CkRv> {
    let mut out = vec![0u8; len];
    macro_rules! run {
        ($H:ty) => {{
            let hk = hkdf::Hkdf::<$H>::new(salt, ikm);
            hk.expand(info, &mut out).map_err(|_| CKR_KEY_SIZE_RANGE)?;
        }};
    }
    match prf {
        CKM_SHA384 => run!(sha2::Sha384),
        CKM_SHA512 => run!(sha2::Sha512),
        CKM_SHA3_256 => run!(sha3::Sha3_256),
        CKM_SHA3_512 => run!(sha3::Sha3_512),
        CKM_SHA256 => run!(sha2::Sha256),
        _ => return Err(CKR_MECHANISM_INVALID),
    }
    Ok(out)
}

/// A finalize step applied to the running concatenated secret of a
/// [`Combiner::Concat`], each a standard PKCS#11 v3.2 derive mechanism.
#[derive(Clone, Debug)]
pub enum FinalizeStep {
    /// `CKM_CONCATENATE_BASE_AND_DATA` — append transcript bytes (ct, pk, label)
    /// onto the running secret (X-Wing: `‖ ct_X ‖ pk_X ‖ XWingLabel`).
    ConcatData(Vec<u8>),
    /// `CKM_SHA*_KEY_DERIVATION` — hash the running secret (SSH
    /// `mlkem768x25519-sha256`: SHA-256; X-Wing: SHA3-256).
    Digest(u32),
    /// HKDF over the running secret as IKM (RFC 5869), `salt`/`info`/`len` as
    /// given. For combiners that KDF rather than plain-hash.
    Hkdf { prf: u32, salt: Vec<u8>, info: Vec<u8>, len: usize },
}

/// A hybrid-KEM shared-secret combiner. Two shapes cover the registered
/// two-component combiners (n-ary keyed-PRF chains — RFC 9370 IKEv2 — are the
/// calling protocol's orchestration, out of scope here; see the revised plan
/// Correction 2).
#[derive(Clone, Debug)]
pub enum Combiner {
    /// Concatenate all components in order (via `CKM_CONCATENATE_BASE_AND_KEY`),
    /// then apply each finalize step. The three IANA TLS groups use
    /// `finalize: []` (PURE concatenation — verified no hash/KDF).
    Concat { finalize: Vec<FinalizeStep> },
    /// HKDF-Extract keying one component with the other (salt = component 0,
    /// IKM = component 1), then Expand — NO concatenation. The dual-PRF shape.
    DualPrf { prf: u32, info: Vec<u8>, len: usize },
}

/// Run a combiner over the component shared secrets, entirely in-HSM, and
/// return the final combined secret bytes. `Concat` composition happens through
/// the audited `concatenate_keys`/`concatenate_data`/`digest_key_derivation`
/// mechanism wrappers (each registers a handle); every intermediate handle is
/// destroyed before returning so no secret objects accumulate per operation.
///
/// The three shipped TLS groups pass `Concat { finalize: [] }`. `DualPrf` and
/// the `Hkdf`/`Digest`/`ConcatData` finalize steps are exercised at this level
/// (proving the mechanisms compose) — see the executor tests.
pub fn run_combiner(
    session: u32,
    components: &[&[u8]],
    combiner: &Combiner,
) -> Result<Vec<u8>, CkRv> {
    match combiner {
        Combiner::Concat { finalize } => {
            if components.is_empty() {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // Register every component + intermediate as a handle; destroy them
            // all at the end (hygiene — they hold component secret material).
            let mut created: Vec<u32> = Vec::new();
            let mut running = register_derived_secret(session, components[0].to_vec());
            created.push(running);
            for comp in &components[1..] {
                let h = register_derived_secret(session, comp.to_vec());
                created.push(h);
                running = concatenate_keys(session, running, h)?;
                created.push(running);
            }
            for step in finalize {
                running = match step {
                    FinalizeStep::ConcatData(data) => concatenate_data(session, running, data)?,
                    FinalizeStep::Digest(mech) => {
                        digest_key_derivation(session, running, *mech, None)?
                    }
                    FinalizeStep::Hkdf { prf, salt, info, len } => {
                        let ikm = get_object_value(running).ok_or(CKR_KEY_HANDLE_INVALID)?;
                        let salt_opt = if salt.is_empty() { None } else { Some(salt.as_slice()) };
                        let out = hkdf_extract_expand(*prf, salt_opt, &ikm, info, *len)?;
                        register_derived_secret(session, out)
                    }
                };
                created.push(running);
            }
            let value = get_object_value(running).ok_or(CKR_FUNCTION_FAILED)?;
            for h in created {
                let _ = crate::native::object::destroy_object(session, h);
            }
            Ok(value)
        }
        Combiner::DualPrf { prf, info, len } => {
            if components.len() != 2 {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // HKDF-Extract(salt = component 0, IKM = component 1), then Expand.
            hkdf_extract_expand(*prf, Some(components[0]), components[1], info, *len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().expect("engine init");
        crate::native::session::bootstrap_default_token(0, "so", "user", "concat-test")
            .expect("bootstrap session")
    }

    /// Register a generic-secret object with a known value, return its handle.
    fn secret_with_value(session: u32, value: &[u8]) -> u32 {
        let mut attrs: Attributes = HashMap::new();
        attrs.insert(CKA_VALUE, value.to_vec());
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        store_ulong(&mut attrs, CKA_VALUE_LEN, value.len() as u32);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        allocate_handle_owned(session, attrs)
    }

    #[test]
    fn concatenate_appends_second_after_base() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Spec §6.43.3 worked example: base 0x01234567, other 0x89ABCDEF →
        // 0x0123456789ABCDEF.
        let base = secret_with_value(session, &[0x01, 0x23, 0x45, 0x67]);
        let second = secret_with_value(session, &[0x89, 0xAB, 0xCD, 0xEF]);
        let out = concatenate_keys(session, base, second).unwrap();
        assert_eq!(
            get_object_value(out).unwrap(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn concatenate_length_is_sum_and_order_matters() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // X25519MLKEM768 shape: ML-KEM ss (32) ‖ X25519 ss (32) = 64 bytes.
        let mlkem = secret_with_value(session, &[0xAA; 32]);
        let x25519 = secret_with_value(session, &[0xBB; 32]);
        let out = concatenate_keys(session, mlkem, x25519).unwrap();
        let v = get_object_value(out).unwrap();
        assert_eq!(v.len(), 64, "sum of the two component lengths");
        assert_eq!(&v[..32], &[0xAA; 32], "base (ML-KEM) first");
        assert_eq!(&v[32..], &[0xBB; 32], "second (X25519) last");
        // Reversed order gives a different secret — the per-variant ordering
        // is load-bearing (X25519MLKEM768 vs SecP256r1MLKEM768).
        let out_rev = concatenate_keys(session, x25519, mlkem).unwrap();
        assert_ne!(get_object_value(out_rev).unwrap(), v);
    }

    #[test]
    fn concatenate_missing_value_is_handle_invalid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let base = secret_with_value(session, &[0x01, 0x02]);
        assert_eq!(
            concatenate_keys(session, base, 0xDEAD_BEEF),
            Err(CKR_KEY_HANDLE_INVALID)
        );
    }

    #[test]
    fn concatenate_data_appends_raw_bytes() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Spec §6.43.4 worked example: base 0x01234567, data 0x89ABCDEF.
        let base = secret_with_value(session, &[0x01, 0x23, 0x45, 0x67]);
        let out = concatenate_data(session, base, &[0x89, 0xAB, 0xCD, 0xEF]).unwrap();
        assert_eq!(
            get_object_value(out).unwrap(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn digest_key_derivation_matches_known_sha256() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Canonical KAT: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        let base = secret_with_value(session, b"abc");
        let out = digest_key_derivation(session, base, CKM_SHA256_KEY_DERIVATION, None).unwrap();
        let expect: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(get_object_value(out).unwrap(), expect);
    }

    #[test]
    fn digest_key_derivation_truncates_to_requested_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // SHA-512 of "abc" truncated to 32 bytes = leftmost 32 of the 64-byte
        // digest (used e.g. to fit a 256-bit AES key out of a hash step).
        let base = secret_with_value(session, b"abc");
        let full =
            digest_key_derivation(session, base, CKM_SHA512_KEY_DERIVATION, None).unwrap();
        let full_v = get_object_value(full).unwrap();
        assert_eq!(full_v.len(), 64);
        let base2 = secret_with_value(session, b"abc");
        let trunc =
            digest_key_derivation(session, base2, CKM_SHA512_KEY_DERIVATION, Some(32)).unwrap();
        assert_eq!(get_object_value(trunc).unwrap(), full_v[..32].to_vec());
    }

    // ── run_combiner executor ────────────────────────────────────────────────

    /// The three IANA TLS groups: `Concat { finalize: [] }` is pure ordered
    /// concatenation of the component secrets.
    #[test]
    fn run_combiner_pure_concat_is_ordered_concatenation() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let ss_mlkem = [0xAA; 32];
        let ss_x25519 = [0xBB; 32];
        let out = run_combiner(
            session,
            &[&ss_mlkem, &ss_x25519],
            &Combiner::Concat { finalize: vec![] },
        )
        .unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(&out[..32], &ss_mlkem, "ML-KEM ss first");
        assert_eq!(&out[32..], &ss_x25519, "X25519 ss last");
    }

    /// SSH `mlkem768x25519-sha256`: `SS = SHA-256(ss_mlkem ‖ ss_x25519)`
    /// (verified from the OpenSSH source vendored in this repo). Expressed as
    /// `Concat { finalize: [Digest(SHA256)] }`.
    #[test]
    fn run_combiner_ssh_sha256_recipe_matches_direct() {
        use sha2::Digest as _;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let ss_mlkem = [0x11; 32];
        let ss_x25519 = [0x22; 32];
        let out = run_combiner(
            session,
            &[&ss_mlkem, &ss_x25519],
            &Combiner::Concat { finalize: vec![FinalizeStep::Digest(CKM_SHA256_KEY_DERIVATION)] },
        )
        .unwrap();
        let expect = sha2::Sha256::digest([ss_mlkem, ss_x25519].concat()).to_vec();
        assert_eq!(out, expect);
    }

    /// X-Wing: `SS = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` (verified
    /// from draft-connolly-cfrg-xwing-kem; ML-KEM ct deliberately omitted).
    /// Expressed as `Concat { finalize: [ConcatData(ct_X‖pk_X‖label), Digest(SHA3_256)] }`.
    #[test]
    fn run_combiner_xwing_sha3_256_recipe_matches_direct() {
        use sha3::Digest as _;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let ss_m = [0x33; 32];
        let ss_x = [0x44; 32];
        let ct_x = [0x55; 32];
        let pk_x = [0x66; 32];
        let label: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]; // "\.//^\"
        let transcript = [ct_x.as_slice(), pk_x.as_slice(), &label].concat();
        let out = run_combiner(
            session,
            &[&ss_m, &ss_x],
            &Combiner::Concat {
                finalize: vec![
                    FinalizeStep::ConcatData(transcript.clone()),
                    FinalizeStep::Digest(CKM_SHA3_256_KEY_DERIVATION),
                ],
            },
        )
        .unwrap();
        let expect =
            sha3::Sha3_256::digest([ss_m.as_slice(), &ss_x, &transcript].concat()).to_vec();
        assert_eq!(out, expect);
    }

    /// DualPrf: `HKDF-Extract(salt = ss1, IKM = ss2)` then Expand — matches a
    /// direct `hkdf` computation (self-consistency; no external KAT claimed).
    #[test]
    fn run_combiner_dualprf_matches_direct_hkdf() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let ss1 = [0x77; 32];
        let ss2 = [0x88; 32];
        let info = b"dual-prf-info";
        let out = run_combiner(
            session,
            &[&ss1, &ss2],
            &Combiner::DualPrf { prf: CKM_SHA256, info: info.to_vec(), len: 32 },
        )
        .unwrap();
        let mut expect = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&ss1), &ss2)
            .expand(info, &mut expect)
            .unwrap();
        assert_eq!(out, expect.to_vec());
    }

    #[test]
    fn digest_key_derivation_rejects_overlong_request_and_bad_mech() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let base = secret_with_value(session, b"abc");
        // Can't stretch a 32-byte SHA-256 to 40 bytes.
        assert_eq!(
            digest_key_derivation(session, base, CKM_SHA256_KEY_DERIVATION, Some(40)),
            Err(CKR_KEY_SIZE_RANGE)
        );
        let base2 = secret_with_value(session, b"abc");
        assert_eq!(
            digest_key_derivation(session, base2, CKM_CONCATENATE_BASE_AND_KEY, None),
            Err(CKR_MECHANISM_INVALID)
        );
    }
}
