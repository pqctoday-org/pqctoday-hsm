//! Raw PKCS#11 v3.2 access for the two operations `cryptoki` cannot express.
//!
//! # Why this module exists
//!
//! X-Wing (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`, ciphersuite
//! `0x004D`) needs ML-KEM encapsulation and SHA3-256. Our engine implements
//! both. The `cryptoki` crate cannot reach either:
//!
//! * **`C_EncapsulateKey` / `C_DecapsulateKey` are PKCS#11 v3.2 functions.**
//!   `cryptoki` 0.10's `Function` enum stops at `CK_FUNCTION_LIST_3_0`. It does
//!   not merely lack a wrapper — it lacks the 3.2 function-list structure the
//!   pointers live in.
//! * **`CKM_SHA3_256` is not in `cryptoki`'s `MechanismType` allowlist.**
//!   `TryFrom<CK_MECHANISM_TYPE>` is an exhaustive `match`, so an unrecognised
//!   mechanism value is rejected rather than passed through.
//!
//! And we cannot borrow `cryptoki`'s session to do the calls ourselves:
//! `Session::handle()` is `pub(crate)`, and the entire public surface of
//! `Session` is `close()`. `ObjectHandle`'s accessors are sealed the same way.
//!
//! (`ObjectHandle` does implement `Display`/`LowerHex`, so a handle *can* be
//! recovered by formatting it and parsing the number back. That is deliberately
//! not done here. Round-tripping a key handle through a decimal string in a
//! crypto path is the kind of shortcut that reads as a bug forever after.)
//!
//! # What it does instead
//!
//! Opens its **own** session on the same slot, through symbols resolved
//! directly from the module. The library is already loaded and `C_Initialize`d
//! by `cryptoki`; `dlopen` on the same path returns the same image, so we
//! attach to the existing instance rather than starting a second one.
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED` is therefore the expected, correct
//! response to our `C_Initialize` and is treated as success.
//!
//! # Symbol resolution, and why not the function list
//!
//! Functions are resolved by name with `dlsym`, not by indexing
//! `CK_FUNCTION_LIST_3_2`. Indexing means asserting that `C_EncapsulateKey`
//! sits at a particular slot — measured at 92 in our build, but that is an
//! artefact of the struct layout, not a contract, and a silent off-by-one there
//! would call an adjacent function with the wrong argument types. Resolving by
//! name is checkable and fails loudly.
//!
//! The trade-off: a PKCS#11 module that exports only `C_GetFunctionList` and
//! hides the rest would not work here. Ours exports all of them (verified), and
//! [`KemFfi::open`] reports precisely which symbol was missing if a different
//! module is ever pointed at this path.

#![cfg(not(target_arch = "wasm32"))]

use std::ffi::c_void;
use std::os::raw::c_uchar;

use crate::error::PqcTodayError;

// ── PKCS#11 types ────────────────────────────────────────────────────────────

type CkRv = std::os::raw::c_ulong;
type CkFlags = std::os::raw::c_ulong;
type CkSlotId = std::os::raw::c_ulong;
type CkSessionHandle = std::os::raw::c_ulong;
type CkObjectHandle = std::os::raw::c_ulong;
type CkMechanismType = std::os::raw::c_ulong;
type CkAttributeType = std::os::raw::c_ulong;
type CkUlong = std::os::raw::c_ulong;

const CKR_OK: CkRv = 0x0000_0000;
const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x0000_0191;

/// `CKF_SERIAL_SESSION | CKF_RW_SESSION` — PKCS#11 v3.2 §5.6.
const CKF_SERIAL_SESSION: CkFlags = 0x0000_0004;
const CKF_RW_SESSION: CkFlags = 0x0000_0002;

const CKU_USER: CkUlong = 1;

// Values below are taken from `src/lib/pkcs11/pkcs11t.h`, the normative header
// vendored in this repo — never from memory. See CLAUDE.md: pkcs11t.h wins.
const CKM_ML_KEM_KEY_PAIR_GEN: CkMechanismType = 0x0000_000f;
const CKM_ML_KEM: CkMechanismType = 0x0000_0017;
const CKM_SHA3_256: CkMechanismType = 0x0000_02b0;
const CKM_SHAKE_256_KEY_DERIVATION: CkMechanismType = 0x0000_039c;

const CKA_CLASS: CkAttributeType = 0x0000_0000;
const CKA_TOKEN: CkAttributeType = 0x0000_0001;
const CKA_VALUE: CkAttributeType = 0x0000_0011;
const CKA_KEY_TYPE: CkAttributeType = 0x0000_0100;
const CKA_SENSITIVE: CkAttributeType = 0x0000_0103;
const CKA_EXTRACTABLE: CkAttributeType = 0x0000_0162;
const CKA_VALUE_LEN: CkAttributeType = 0x0000_0161;
/// Without this on the KDF's base key, `C_DeriveKey` returns
/// `CKR_KEY_FUNCTION_NOT_PERMITTED` (0x68) — the object exists and is readable,
/// it simply is not allowed to be derived from.
const CKA_DERIVE: CkAttributeType = 0x0000_010c;
const CKA_PARAMETER_SET: CkAttributeType = 0x0000_061d;
const CKA_SEED: CkAttributeType = 0x0000_0637;

const CKM_CHACHA20_POLY1305: CkMechanismType = 0x0000_4021;
const CKK_CHACHA20: CkUlong = 0x0000_0033;

/// `CK_SALSA20_CHACHA20_POLY1305_PARAMS`, pkcs11t.h line 2564.
#[repr(C)]
struct CkChaChaParams {
    p_nonce: *mut u8,
    nonce_len: CkUlong,
    p_aad: *mut u8,
    aad_len: CkUlong,
}

const CKO_SECRET_KEY: CkUlong = 0x0000_0004;
const CKO_PUBLIC_KEY: CkUlong = 0x0000_0002;
const CKK_ML_KEM: CkUlong = 0x0000_0049;
const CKA_ENCAPSULATE: CkAttributeType = 0x0000_0633;
const CKK_GENERIC_SECRET: CkUlong = 0x0000_0010;
const CKP_ML_KEM_768: CkUlong = 0x0000_0002;

#[repr(C)]
struct CkMechanism {
    mechanism: CkMechanismType,
    p_parameter: *mut c_void,
    parameter_len: CkUlong,
}

#[repr(C)]
struct CkAttribute {
    attr_type: CkAttributeType,
    p_value: *mut c_void,
    value_len: CkUlong,
}

// ── Function signatures ──────────────────────────────────────────────────────

type FnInitialize = unsafe extern "C" fn(*mut c_void) -> CkRv;
type FnOpenSession = unsafe extern "C" fn(
    CkSlotId,
    CkFlags,
    *mut c_void,
    *mut c_void,
    *mut CkSessionHandle,
) -> CkRv;
type FnCloseSession = unsafe extern "C" fn(CkSessionHandle) -> CkRv;
type FnLogin = unsafe extern "C" fn(CkSessionHandle, CkUlong, *const c_uchar, CkUlong) -> CkRv;
type FnGenerateKeyPair = unsafe extern "C" fn(
    CkSessionHandle,
    *const CkMechanism,
    *const CkAttribute,
    CkUlong,
    *const CkAttribute,
    CkUlong,
    *mut CkObjectHandle,
    *mut CkObjectHandle,
) -> CkRv;
type FnEncapsulateKey = unsafe extern "C" fn(
    CkSessionHandle,
    *const CkMechanism,
    CkObjectHandle,
    *const CkAttribute,
    CkUlong,
    *mut c_uchar,
    *mut CkUlong,
    *mut CkObjectHandle,
) -> CkRv;
type FnDecapsulateKey = unsafe extern "C" fn(
    CkSessionHandle,
    *const CkMechanism,
    CkObjectHandle,
    *const CkAttribute,
    CkUlong,
    *const c_uchar,
    CkUlong,
    *mut CkObjectHandle,
) -> CkRv;
type FnGetAttributeValue =
    unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, *mut CkAttribute, CkUlong) -> CkRv;
type FnDeriveKey = unsafe extern "C" fn(
    CkSessionHandle,
    *const CkMechanism,
    CkObjectHandle,
    *const CkAttribute,
    CkUlong,
    *mut CkObjectHandle,
) -> CkRv;
type FnCreateObject = unsafe extern "C" fn(
    CkSessionHandle,
    *const CkAttribute,
    CkUlong,
    *mut CkObjectHandle,
) -> CkRv;
type FnCryptInit =
    unsafe extern "C" fn(CkSessionHandle, *const CkMechanism, CkObjectHandle) -> CkRv;
type FnCrypt = unsafe extern "C" fn(
    CkSessionHandle,
    *const c_uchar,
    CkUlong,
    *mut c_uchar,
    *mut CkUlong,
) -> CkRv;
type FnDigestInit = unsafe extern "C" fn(CkSessionHandle, *const CkMechanism) -> CkRv;
type FnDigest = unsafe extern "C" fn(
    CkSessionHandle,
    *const c_uchar,
    CkUlong,
    *mut c_uchar,
    *mut CkUlong,
) -> CkRv;

// ── The FFI handle ───────────────────────────────────────────────────────────

/// Own session onto the PKCS#11 module, for the v3.2 operations `cryptoki`
/// cannot reach. Independent of the `cryptoki` session; shares only the slot.
pub struct KemFfi {
    // Held to keep the library loaded for the lifetime of the resolved symbols.
    _lib: libloading::Library,
    session: CkSessionHandle,
    /// Serialises access to `session`. PKCS#11 gives no thread-safety guarantee
    /// for concurrent calls on one session handle — CKF_SERIAL_SESSION is a
    /// promise we make to the module, not one it makes to us.
    call_lock: std::sync::Mutex<()>,

    close_session: FnCloseSession,
    generate_key_pair: FnGenerateKeyPair,
    encapsulate: FnEncapsulateKey,
    decapsulate: FnDecapsulateKey,
    get_attribute_value: FnGetAttributeValue,
    derive_key: FnDeriveKey,
    create_object: FnCreateObject,
    digest_init: FnDigestInit,
    digest: FnDigest,
    encrypt_init: FnCryptInit,
    encrypt_op: FnCrypt,
    decrypt_init: FnCryptInit,
    decrypt_op: FnCrypt,
}

// Safety: the raw pointers are function addresses in a module that is never
// unloaded while this lives, so they are valid to call from any thread. Shared
// mutable state — the session — is behind `call_lock`; see below.
//
// An earlier version of this comment claimed CKF_SERIAL_SESSION meant "the
// module serialises calls for us". That is backwards, and it caused a SIGSEGV
// under `cargo test`'s default parallelism. The flag is the APPLICATION
// promising not to make concurrent calls on the session. Honouring that promise
// is our job, and `call_lock` is how.
unsafe impl Send for KemFfi {}
unsafe impl Sync for KemFfi {}

macro_rules! sym {
    ($lib:expr, $name:literal, $ty:ty) => {{
        let n: &[u8] = concat!($name, "\0").as_bytes();
        // Safety: the symbol's type is asserted here and matches the PKCS#11
        // v3.2 prototype transcribed above from the vendored pkcs11f.h.
        let s: libloading::Symbol<$ty> = unsafe {
            $lib.get(n).map_err(|_| {
                PqcTodayError::Kem(format!(
                    "PKCS#11 module does not export {} — this module needs the \
                     v3.2 entry points resolvable by name",
                    $name
                ))
            })?
        };
        *s
    }};
}

impl KemFfi {
    /// Attach to the already-loaded module and open an independent session on
    /// `slot_id`.
    ///
    /// `module_path` must be the same path `cryptoki` was given, so `dlopen`
    /// returns the same image and we share its initialised state.
    pub fn open(
        module_path: &std::path::Path,
        slot_id: u64,
        user_pin: Option<&str>,
    ) -> Result<Self, PqcTodayError> {
        // Safety: loading a PKCS#11 module is what this crate exists to do; the
        // path comes from the caller's own HsmConfig.
        let lib = unsafe { libloading::Library::new(module_path) }.map_err(|e| {
            PqcTodayError::Kem(format!("cannot load PKCS#11 module for KEM path: {e}"))
        })?;

        let initialize = sym!(lib, "C_Initialize", FnInitialize);
        let open_session = sym!(lib, "C_OpenSession", FnOpenSession);
        let close_session = sym!(lib, "C_CloseSession", FnCloseSession);
        let login = sym!(lib, "C_Login", FnLogin);
        let generate_key_pair = sym!(lib, "C_GenerateKeyPair", FnGenerateKeyPair);
        let encapsulate = sym!(lib, "C_EncapsulateKey", FnEncapsulateKey);
        let decapsulate = sym!(lib, "C_DecapsulateKey", FnDecapsulateKey);
        let get_attribute_value = sym!(lib, "C_GetAttributeValue", FnGetAttributeValue);
        let derive_key = sym!(lib, "C_DeriveKey", FnDeriveKey);
        let create_object = sym!(lib, "C_CreateObject", FnCreateObject);
        let digest_init = sym!(lib, "C_DigestInit", FnDigestInit);
        let digest = sym!(lib, "C_Digest", FnDigest);
        let encrypt_init = sym!(lib, "C_EncryptInit", FnCryptInit);
        let encrypt_op = sym!(lib, "C_Encrypt", FnCrypt);
        let decrypt_init = sym!(lib, "C_DecryptInit", FnCryptInit);
        let decrypt_op = sym!(lib, "C_Decrypt", FnCrypt);

        // The module is already initialised by cryptoki. ALREADY_INITIALIZED is
        // the expected answer and means exactly what we want: we are attached to
        // the live instance, not a second one.
        // Safety: NULL args means "no threading callbacks", per §5.6.
        let rv = unsafe { initialize(std::ptr::null_mut()) };
        if rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
            return Err(PqcTodayError::Kem(format!(
                "C_Initialize for KEM path failed: 0x{rv:08x}"
            )));
        }

        let mut session: CkSessionHandle = 0;
        // Safety: out-param is a live local; NULL notify/app per §5.6.
        let rv = unsafe {
            open_session(
                slot_id as CkSlotId,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut session,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_OpenSession for KEM path failed: 0x{rv:08x}"
            )));
        }

        if let Some(pin) = user_pin {
            // Safety: pin bytes outlive the call.
            let rv = unsafe { login(session, CKU_USER, pin.as_ptr(), pin.len() as CkUlong) };
            // Already logged in on this token is fine — login state is per-token,
            // and cryptoki's session may have got there first.
            const CKR_USER_ALREADY_LOGGED_IN: CkRv = 0x0000_0100;
            if rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN {
                // Safety: session handle is valid.
                unsafe { close_session(session) };
                return Err(PqcTodayError::Kem(format!(
                    "C_Login for KEM path failed: 0x{rv:08x}"
                )));
            }
        }

        Ok(Self {
            _lib: lib,
            session,
            call_lock: std::sync::Mutex::new(()),
            close_session,
            generate_key_pair,
            encapsulate,
            decapsulate,
            get_attribute_value,
            derive_key,
            create_object,
            digest_init,
            digest,
            encrypt_init,
            encrypt_op,
            decrypt_init,
            decrypt_op,
        })
    }

    /// SHA3-256. Needed by the X-Wing combiner and unreachable through
    /// `cryptoki`, whose mechanism allowlist has no SHA3 at all.
    pub fn sha3_256(&self, data: &[u8]) -> Result<Vec<u8>, PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        let mech = CkMechanism {
            mechanism: CKM_SHA3_256,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };
        // Safety: mechanism has no parameter; session handle is valid.
        let rv = unsafe { (self.digest_init)(self.session, &mech) };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_DigestInit(SHA3-256) failed: 0x{rv:08x}"
            )));
        }

        let mut out = vec![0u8; 32];
        let mut out_len: CkUlong = 32;
        // Safety: `out` is 32 bytes and `out_len` says so; SHA3-256 emits 32.
        let rv = unsafe {
            (self.digest)(
                self.session,
                data.as_ptr(),
                data.len() as CkUlong,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_Digest(SHA3-256) failed: 0x{rv:08x}"
            )));
        }
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// SHAKE-256 as an extendable-output function, squeezing `out_len` bytes
    /// from `input`, entirely inside the token.
    ///
    /// X-Wing's decapsulation key is a 32-byte seed expanded to 96 bytes — 64
    /// for ML-KEM's `KeyGen_internal(d, z)` and 32 for the X25519 scalar. Doing
    /// that expansion in software would derive the private key outside the HSM
    /// while still calling the result HSM-backed, so it runs here instead
    /// (`CKM_SHAKE_256_KEY_DERIVATION`, added to the engine for this).
    ///
    /// Implemented as import-then-derive: PKCS#11 KDFs operate on a key object,
    /// not a byte string, so the input is first created as a session-only
    /// generic secret. Both objects die with the session.
    pub fn shake256(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>, PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        let base = self.import_secret(input)?;
        let mech = CkMechanism {
            mechanism: CKM_SHAKE_256_KEY_DERIVATION,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };

        let mut value_len: CkUlong = out_len as CkUlong;
        let tmpl = SecretTemplate::new();
        // CKA_VALUE_LEN is mandatory here: an XOF has no natural output size,
        // so the engine rejects a template without it rather than guessing.
        let mut attrs: Vec<CkAttribute> = Vec::with_capacity(5);
        for a in tmpl.attrs.iter() {
            attrs.push(CkAttribute {
                attr_type: a.attr_type,
                p_value: a.p_value,
                value_len: a.value_len,
            });
        }
        attrs.push(CkAttribute {
            attr_type: CKA_VALUE_LEN,
            p_value: &mut value_len as *mut _ as *mut c_void,
            value_len: std::mem::size_of::<CkUlong>() as CkUlong,
        });

        let mut h_out: CkObjectHandle = 0;
        // Safety: template and its backing store outlive the call.
        let rv = unsafe {
            (self.derive_key)(
                self.session,
                &mech,
                base,
                attrs.as_ptr(),
                attrs.len() as CkUlong,
                &mut h_out,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_DeriveKey(SHAKE-256, {out_len} bytes) failed: 0x{rv:08x}"
            )));
        }

        let out = self.read_secret(h_out)?;
        if out.len() != out_len {
            return Err(PqcTodayError::Kem(format!(
                "SHAKE-256 returned {} bytes, expected {out_len}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Import raw bytes as a session-only generic secret so a KDF can consume
    /// them. Marked extractable and non-sensitive: it is KDF input we already
    /// hold in memory, and the derived output has to be readable anyway.
    fn import_secret(&self, value: &[u8]) -> Result<CkObjectHandle, PqcTodayError> {
        self.import_secret_of_type(value, CKK_GENERIC_SECRET)
    }

    fn import_secret_of_type(
        &self,
        value: &[u8],
        kt: CkUlong,
    ) -> Result<CkObjectHandle, PqcTodayError> {
        let mut class = CKO_SECRET_KEY;
        let mut key_type = kt;
        let mut ck_false: u8 = 0;
        let mut ck_true: u8 = 1;
        let mut val = value.to_vec();

        let tmpl = [
            CkAttribute {
                attr_type: CKA_CLASS,
                p_value: &mut class as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_KEY_TYPE,
                p_value: &mut key_type as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_TOKEN,
                p_value: &mut ck_false as *mut _ as *mut c_void,
                value_len: 1,
            },
            CkAttribute {
                attr_type: CKA_SENSITIVE,
                p_value: &mut ck_false as *mut _ as *mut c_void,
                value_len: 1,
            },
            CkAttribute {
                attr_type: CKA_EXTRACTABLE,
                p_value: &mut ck_true as *mut _ as *mut c_void,
                value_len: 1,
            },
            // Required, and not obviously so: without CKA_DERIVE the object is
            // created happily and C_DeriveKey then fails with
            // CKR_KEY_FUNCTION_NOT_PERMITTED, which reads like a mechanism
            // problem rather than a missing attribute on the input.
            CkAttribute {
                attr_type: CKA_DERIVE,
                p_value: &mut ck_true as *mut _ as *mut c_void,
                value_len: 1,
            },
            CkAttribute {
                attr_type: CKA_VALUE,
                p_value: val.as_mut_ptr() as *mut c_void,
                value_len: val.len() as CkUlong,
            },
        ];

        let mut h: CkObjectHandle = 0;
        // Safety: template and `val` outlive the call.
        let rv = unsafe {
            (self.create_object)(self.session, tmpl.as_ptr(), tmpl.len() as CkUlong, &mut h)
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_CreateObject for KDF input failed: 0x{rv:08x}"
            )));
        }
        Ok(h)
    }

    /// ChaCha20-Poly1305 AEAD, inside the HSM.
    ///
    /// `encrypt == true` seals (returns ciphertext ‖ 16-byte tag), otherwise it
    /// opens. Used by MLS ciphersuites 3 and `0x004D`.
    ///
    /// The engine has had `CKM_CHACHA20_POLY1305` since 2026-06; `cryptoki`
    /// still cannot name it, because its `MechanismType` conversion is an
    /// exhaustive allowlist with no ChaCha entry. `crypto.rs` therefore fell
    /// back to a software implementation and carried a comment saying the HSM
    /// could not do it — true when written, out of date since.
    pub fn chacha20_poly1305(
        &self,
        encrypt: bool,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        if key.len() != 32 {
            return Err(PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 key must be 32 bytes, got {}",
                key.len()
            )));
        }
        if nonce.len() != 12 {
            return Err(PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let h_key = self.import_secret_of_type(key, CKK_CHACHA20)?;

        // CK_SALSA20_CHACHA20_POLY1305_PARAMS: pNonce, ulNonceLen, pAAD, ulAADLen.
        // Buffers are bound to locals so they outlive the call.
        let mut nonce_buf = nonce.to_vec();
        let mut aad_buf = aad.to_vec();
        let mut params = CkChaChaParams {
            p_nonce: nonce_buf.as_mut_ptr(),
            // BYTES, not bits. The engine checks `ulNonceLen != 12` directly
            // (SoftHSM_cipher.cpp), so a bit count silently fails the check.
            nonce_len: nonce_buf.len() as CkUlong,
            p_aad: if aad_buf.is_empty() {
                std::ptr::null_mut()
            } else {
                aad_buf.as_mut_ptr()
            },
            aad_len: aad_buf.len() as CkUlong,
        };
        let mech = CkMechanism {
            mechanism: CKM_CHACHA20_POLY1305,
            p_parameter: &mut params as *mut _ as *mut c_void,
            parameter_len: std::mem::size_of::<CkChaChaParams>() as CkUlong,
        };

        let (init, oneshot): (FnCryptInit, FnCrypt) = if encrypt {
            (self.encrypt_init, self.encrypt_op)
        } else {
            (self.decrypt_init, self.decrypt_op)
        };

        // Safety: mechanism parameter and its buffers outlive the call.
        let rv = unsafe { init(self.session, &mech, h_key) };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 {} init failed: 0x{rv:08x}",
                if encrypt { "encrypt" } else { "decrypt" }
            )));
        }

        // Length probe, then the real call — the tag makes the output length
        // differ from the input in both directions, so it is not assumed.
        let mut out_len: CkUlong = 0;
        // Safety: NULL output buffer is the defined length-probe form.
        let rv = unsafe {
            oneshot(
                self.session,
                input.as_ptr(),
                input.len() as CkUlong,
                std::ptr::null_mut(),
                &mut out_len,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 length probe failed: 0x{rv:08x}"
            )));
        }

        let mut out = vec![0u8; out_len as usize];
        // Safety: `out` is `out_len` bytes, as just reported.
        let rv = unsafe {
            oneshot(
                self.session,
                input.as_ptr(),
                input.len() as CkUlong,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "ChaCha20-Poly1305 {} failed: 0x{rv:08x}",
                if encrypt { "encrypt" } else { "decrypt" }
            )));
        }
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// Generate an ML-KEM-768 key pair on the token.
    /// Returns `(public_handle, private_handle)`.
    pub fn ml_kem_768_keygen(&self) -> Result<(u64, u64), PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        self.keygen_inner(None)
    }

    fn keygen_inner(&self, seed: Option<&[u8]>) -> Result<(u64, u64), PqcTodayError> {
        let mech = CkMechanism {
            mechanism: CKM_ML_KEM_KEY_PAIR_GEN,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };
        let mut param_set: CkUlong = CKP_ML_KEM_768;
        let mut ck_false: u8 = 0;
        let mut ck_true: u8 = 1;

        let pub_tmpl = [
            CkAttribute {
                attr_type: CKA_PARAMETER_SET,
                p_value: &mut param_set as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_TOKEN,
                p_value: &mut ck_false as *mut _ as *mut c_void,
                value_len: 1,
            },
        ];
        // Session key, extractable, not sensitive: the X-Wing combiner runs over
        // the raw shared secret, so it has to come back out. It never touches
        // the token and dies with the session.
        let priv_tmpl = [
            CkAttribute {
                attr_type: CKA_PARAMETER_SET,
                p_value: &mut param_set as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_TOKEN,
                p_value: &mut ck_false as *mut _ as *mut c_void,
                value_len: 1,
            },
            CkAttribute {
                attr_type: CKA_EXTRACTABLE,
                p_value: &mut ck_true as *mut _ as *mut c_void,
                value_len: 1,
            },
        ];

        // Deterministic keygen: append CKA_SEED. The vector must outlive the
        // call, so it is bound here rather than built inline.
        let mut seed_buf = seed.map(|s| s.to_vec());
        let mut priv_attrs: Vec<CkAttribute> = priv_tmpl
            .iter()
            .map(|a| CkAttribute { attr_type: a.attr_type, p_value: a.p_value, value_len: a.value_len })
            .collect();
        if let Some(sb) = seed_buf.as_mut() {
            priv_attrs.push(CkAttribute {
                attr_type: CKA_SEED,
                p_value: sb.as_mut_ptr() as *mut c_void,
                value_len: sb.len() as CkUlong,
            });
        }

        let mut h_pub: CkObjectHandle = 0;
        let mut h_priv: CkObjectHandle = 0;
        // Safety: templates outlive the call; out-params are live locals.
        let rv = unsafe {
            (self.generate_key_pair)(
                self.session,
                &mech,
                pub_tmpl.as_ptr(),
                pub_tmpl.len() as CkUlong,
                priv_attrs.as_ptr(),
                priv_attrs.len() as CkUlong,
                &mut h_pub,
                &mut h_priv,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_GenerateKeyPair(ML-KEM-768) failed: 0x{rv:08x}"
            )));
        }
        Ok((h_pub as u64, h_priv as u64))
    }

    /// Deterministic ML-KEM-768 key generation from a 64-byte `d ‖ z` seed
    /// (FIPS 203 `KeyGen_internal`), via `CKA_SEED`.
    ///
    /// X-Wing needs this: its keypair is defined as a function of a seed, so a
    /// randomly generated ML-KEM key cannot reproduce a published test vector
    /// and cannot round-trip through X-Wing's 32-byte private key encoding.
    pub fn ml_kem_768_keygen_from_seed(&self, seed: &[u8]) -> Result<(u64, u64), PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        if seed.len() != 64 {
            return Err(PqcTodayError::Kem(format!(
                "ML-KEM seed must be 64 bytes (d ‖ z), got {}",
                seed.len()
            )));
        }
        self.keygen_inner(Some(seed))
    }

    /// Read an ML-KEM public key's raw bytes.
    pub fn read_public_key(&self, handle: u64) -> Result<Vec<u8>, PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        self.read_attribute(handle as CkObjectHandle, CKA_VALUE)
    }

    /// ML-KEM encapsulation. Returns `(ciphertext, shared_secret)`.
    ///
    /// Two calls: the first with a NULL buffer to learn the ciphertext length
    /// (§5.2's standard probe), the second to fill it. The shared secret comes
    /// back as an object handle, so it is read out with `C_GetAttributeValue`.
    pub fn ml_kem_encapsulate(&self, public_handle: u64) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        self.encapsulate_locked(public_handle as CkObjectHandle)
    }

    /// Caller must already hold `call_lock`.
    fn encapsulate_locked(
        &self,
        public_handle: CkObjectHandle,
    ) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        let mech = CkMechanism {
            mechanism: CKM_ML_KEM,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };
        let tmpl = self.secret_template();

        let mut ct_len: CkUlong = 0;
        let mut h_secret: CkObjectHandle = 0;
        // Safety: NULL ciphertext buffer is the defined length-probe form.
        let rv = unsafe {
            (self.encapsulate)(
                self.session,
                &mech,
                public_handle,
                tmpl.attrs.as_ptr(),
                tmpl.attrs.len() as CkUlong,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_secret,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_EncapsulateKey length probe failed: 0x{rv:08x}"
            )));
        }

        let mut ct = vec![0u8; ct_len as usize];
        // Safety: `ct` is `ct_len` bytes, as just reported by the probe.
        let rv = unsafe {
            (self.encapsulate)(
                self.session,
                &mech,
                public_handle,
                tmpl.attrs.as_ptr(),
                tmpl.attrs.len() as CkUlong,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_secret,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_EncapsulateKey failed: 0x{rv:08x}"
            )));
        }
        ct.truncate(ct_len as usize);

        let ss = self.read_secret(h_secret)?;
        Ok((ct, ss))
    }

    /// Encapsulate against a raw ML-KEM-768 encapsulation key.
    ///
    /// The sender only ever has the peer's public key as bytes off the wire, so
    /// it is imported as a session object first. PKCS#11 has no
    /// encapsulate-against-raw-bytes form.
    pub fn ml_kem_encapsulate_to(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        let mut class = CKO_PUBLIC_KEY;
        let mut key_type = CKK_ML_KEM;
        let mut param_set: CkUlong = CKP_ML_KEM_768;
        let mut ck_false: u8 = 0;
        let mut ck_true: u8 = 1;
        let mut val = pk.to_vec();

        let tmpl = [
            CkAttribute { attr_type: CKA_CLASS, p_value: &mut class as *mut _ as *mut c_void,
                          value_len: std::mem::size_of::<CkUlong>() as CkUlong },
            CkAttribute { attr_type: CKA_KEY_TYPE, p_value: &mut key_type as *mut _ as *mut c_void,
                          value_len: std::mem::size_of::<CkUlong>() as CkUlong },
            CkAttribute { attr_type: CKA_PARAMETER_SET, p_value: &mut param_set as *mut _ as *mut c_void,
                          value_len: std::mem::size_of::<CkUlong>() as CkUlong },
            CkAttribute { attr_type: CKA_TOKEN, p_value: &mut ck_false as *mut _ as *mut c_void,
                          value_len: 1 },
            CkAttribute { attr_type: CKA_ENCAPSULATE, p_value: &mut ck_true as *mut _ as *mut c_void,
                          value_len: 1 },
            CkAttribute { attr_type: CKA_VALUE, p_value: val.as_mut_ptr() as *mut c_void,
                          value_len: val.len() as CkUlong },
        ];

        let mut h: CkObjectHandle = 0;
        // Safety: template and `val` outlive the call.
        let rv = unsafe {
            (self.create_object)(self.session, tmpl.as_ptr(), tmpl.len() as CkUlong, &mut h)
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "importing the peer ML-KEM encapsulation key failed: 0x{rv:08x}"
            )));
        }
        // NOT self.ml_kem_encapsulate(): we already hold call_lock and a
        // std Mutex is not reentrant, so that would deadlock.
        self.encapsulate_locked(h)
    }

    /// ML-KEM decapsulation. Returns the shared secret.
    pub fn ml_kem_decapsulate(
        &self,
        private_handle: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PqcTodayError> {
        let _guard = self.call_lock.lock().map_err(|_| {
            PqcTodayError::Kem("KEM session lock poisoned".into())
        })?;
        let mech = CkMechanism {
            mechanism: CKM_ML_KEM,
            p_parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };
        let tmpl = self.secret_template();

        let mut h_secret: CkObjectHandle = 0;
        // Safety: ciphertext outlives the call; out-param is a live local.
        let rv = unsafe {
            (self.decapsulate)(
                self.session,
                &mech,
                private_handle as CkObjectHandle,
                tmpl.attrs.as_ptr(),
                tmpl.attrs.len() as CkUlong,
                ciphertext.as_ptr(),
                ciphertext.len() as CkUlong,
                &mut h_secret,
            )
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_DecapsulateKey failed: 0x{rv:08x}"
            )));
        }
        self.read_secret(h_secret)
    }

    /// Template for the derived shared-secret object. Kept in one place so
    /// encapsulate and decapsulate cannot drift apart — if they asked for
    /// different attributes, the two sides would produce objects that compare
    /// unequal for reasons unrelated to the cryptography.
    fn secret_template(&self) -> SecretTemplate {
        SecretTemplate::new()
    }

    /// Read `CKA_VALUE` off a derived secret object.
    fn read_secret(&self, handle: CkObjectHandle) -> Result<Vec<u8>, PqcTodayError> {
        self.read_attribute(handle, CKA_VALUE)
    }

    fn read_attribute(
        &self,
        handle: CkObjectHandle,
        attr_type: CkAttributeType,
    ) -> Result<Vec<u8>, PqcTodayError> {
        let mut probe = [CkAttribute {
            attr_type,
            p_value: std::ptr::null_mut(),
            value_len: 0,
        }];
        // Safety: NULL p_value is the defined length-probe form (§5.7).
        let rv = unsafe {
            (self.get_attribute_value)(self.session, handle, probe.as_mut_ptr(), 1)
        };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_GetAttributeValue(CKA_VALUE) probe failed: 0x{rv:08x} — the \
                 derived secret is probably not extractable"
            )));
        }

        let mut buf = vec![0u8; probe[0].value_len as usize];
        let mut attr = [CkAttribute {
            attr_type,
            p_value: buf.as_mut_ptr() as *mut c_void,
            value_len: probe[0].value_len,
        }];
        // Safety: buffer is exactly the length the probe reported.
        let rv =
            unsafe { (self.get_attribute_value)(self.session, handle, attr.as_mut_ptr(), 1) };
        if rv != CKR_OK {
            return Err(PqcTodayError::Kem(format!(
                "C_GetAttributeValue(CKA_VALUE) failed: 0x{rv:08x}"
            )));
        }
        Ok(buf)
    }
}

/// Owns the attribute backing store so the pointers in `attrs` stay valid.
/// Returning a bare `[CkAttribute; N]` from a helper would leave those pointers
/// dangling at the caller — the values they point at would have been locals of
/// the helper.
struct SecretTemplate {
    attrs: [CkAttribute; 4],
    _class: Box<CkUlong>,
    _key_type: Box<CkUlong>,
    _flags: Box<[u8; 2]>,
}

impl SecretTemplate {
    fn new() -> Self {
        let mut class = Box::new(CKO_SECRET_KEY);
        let mut key_type = Box::new(CKK_GENERIC_SECRET);
        // [0] = CKA_SENSITIVE false, [1] = CKA_EXTRACTABLE true.
        let mut flags = Box::new([0u8, 1u8]);

        let attrs = [
            CkAttribute {
                attr_type: CKA_CLASS,
                p_value: &mut *class as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_KEY_TYPE,
                p_value: &mut *key_type as *mut _ as *mut c_void,
                value_len: std::mem::size_of::<CkUlong>() as CkUlong,
            },
            CkAttribute {
                attr_type: CKA_SENSITIVE,
                p_value: &mut flags[0] as *mut _ as *mut c_void,
                value_len: 1,
            },
            CkAttribute {
                attr_type: CKA_EXTRACTABLE,
                p_value: &mut flags[1] as *mut _ as *mut c_void,
                value_len: 1,
            },
        ];

        Self {
            attrs,
            _class: class,
            _key_type: key_type,
            _flags: flags,
        }
    }
}

impl Drop for KemFfi {
    fn drop(&mut self) {
        // Safety: session handle was returned by C_OpenSession and is closed
        // exactly once. Errors are ignored — there is nothing useful to do with
        // a failure here, and panicking in Drop is worse.
        unsafe { (self.close_session)(self.session) };
    }
}
