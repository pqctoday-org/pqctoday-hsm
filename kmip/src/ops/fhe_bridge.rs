//! KMIP 3.0 PKCS#11-operation (0x33) binding for FHE key custody: interface `PQCTODAY_FHE_1_0` (plan D02387 WP-B,
//! owner decisions F2, F3, F8).
//!
//! Compiled in every native server build (`fhe-custody`, part of `native`) and served only when the server is
//! started with `--fhe-custody`. The default engine build holds CKKS custody only; TFHE seeds need an engine built
//! with `educational-fhe` (TFHE-rs: non-commercial use only, owner decision F10).
//!
//! **One KMIP function = one PKCS#11 call** (owner decision 2026-10-15: PKCS#11 over TTLV first, a KMIP-level
//! abstraction is a later step). The engine's own checks apply unchanged: role, policy binding, decryption policy
//! (counters, recipients, CKKS release rules), the public-export ledger. Decryption follows the PKCS#11 multi-step
//! model: `C_DecryptInit`, then `C_Decrypt` (size query, then the call with a buffer).
//!
//! What the bridge adds, because PKCS#11 operation state now spans KMIP requests and connections:
//! - an operation started by one client cannot be continued or overwritten by another (`CKR_OPERATION_ACTIVE` /
//!   `CKR_OPERATION_NOT_INITIALIZED`); a client is its TLS client-certificate hash, else its authenticated name;
//! - an abandoned operation expires after [`OP_TTL`] and is cancelled in the engine;
//! - public objects created by `C_DeriveKey` and not destroyed within [`OBJECT_TTL`] are destroyed;
//!
//! Roles follow the PKCS#11 v3.2 security model, as for every other key (owner decisions 2026-10-15): functions 1-6
//! are normal-user operations in the client's user session, exactly like KMIP Create or Decrypt on other keys; no
//! FHE-specific role. Per-key limits are key attributes and the enrolled policies. FHE seeds are created with
//! `CKA_DESTROYABLE = FALSE`, so the token refuses `C_DestroyObject` on them; the security officer's signed
//! `[7] destroyFheSeed` is the only way to remove one. Functions 7-8 are the security officer's, the same single SO
//! identity as the replication admin interface (`replication-admin` client certificate).
//!
//! Wire layout (version 1). `Function` is the KMIP PKCS#11 Function value, the 1-based offset (KMIP 3.0 §11.39).
//! Every DER input is decoded strictly (canonical re-encoding, nothing trailing). Objects are named by their
//! `CKA_UNIQUE_ID` (36 bytes). See `kmip/docs/FHE_CUSTODY_INTERFACE.md`.
//!
//! | Function | PKCS#11 call | Role | Input | Output |
//! |---|---|---|---|---|
//! | 1 | `C_GenerateKey(CKM_PQCTODAY_FHE_KEY_GEN)` | user | `GenerateKeyV1` | new seed's unique ID |
//! | 2 | `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)` | user | `DeriveKeyV1` | new public object's unique ID |
//! | 3 | `C_GetAttributeValue` | user | `GetAttributeValueV1` | `AttributesV1` |
//! | 4 | `C_DestroyObject` | user | unique ID | empty |
//! | 5 | `C_DecryptInit(CKM_PQCTODAY_FHE_DECRYPT)` | user | `DecryptInitV1` | empty |
//! | 6 | `C_Decrypt` | user | `DecryptV1` | the data, or (size query) its length as a DER INTEGER |
//! | 7 | `C_PQCTODAY_AdminIssueNonce` | SO (`replication-admin`) | empty | nonce (32 bytes) |
//! | 8 | `C_PQCTODAY_AdminExecute` | SO (`replication-admin`) | `AdminSignedRequest`, operation [5], [6] or [7] | `AdminReceipt` |

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use der::asn1::{OctetString, Utf8StringRef};
use der::Sequence;
use softhsmrustv3::constants::*;
use softhsmrustv3::native::{CKA_ID, CKA_LABEL};
use softhsmrustv3::replication as repl;

use super::engine_bridge::{by_uid, so_call, CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_FUNCTION_NOT_SUPPORTED, CKR_USER_NOT_LOGGED_IN, CKR_USER_TYPE_INVALID};

pub const IFACE: &str = "PQCTODAY_FHE_1_0";
/// mTLS client-certificate CN of the security officer: the one SO identity of the token, shared with the replication
/// admin interface (owner decision 2026-10-15).
pub const ROLE_ADMIN_CN: &str = super::engine_bridge::ROLE_SO_CN;
/// Largest output one call returns: the TFHE compressed server key is about 29 MiB and is read in one
/// `C_GetAttributeValue` (owner decision 2026-10-15). Only replies are this large; the listener still caps an incoming
/// request frame at 16 MiB.
pub const MAX_OUTPUT: usize = 48 * 1024 * 1024;
/// A decryption started with `C_DecryptInit` and not finished within this time is cancelled.
pub const OP_TTL: Duration = Duration::from_secs(120);
/// A public object created by `C_DeriveKey` and not destroyed within this time is destroyed.
pub const OBJECT_TTL: Duration = Duration::from_secs(600);
/// Largest input accepted (a decrypt ciphertext is at most 4 MiB in the engine).
const MAX_INPUT: usize = softhsmrustv3::replication::fhe_custody::MAX_DECRYPT_INPUT + 1024;
const MAX_ATTR: usize = 256;
const MAX_ATTR_TYPES: usize = 16;
const CKR_DATA_LEN_RANGE: u32 = 0x0000_0021;
const W: usize = std::mem::size_of::<usize>();

static SERVED: AtomicBool = AtomicBool::new(false);

/// Bridge state, under one lock: calls are serialised (KMIP connections can share one engine session, and PKCS#11
/// operation state is per session).
struct State {
    /// Engine session → (client, started) of its pending FHE decryption.
    ops: HashMap<u32, (Client, Instant)>,
    /// Derived public objects not yet destroyed: (engine session, handle) → created.
    objects: HashMap<(u32, u32), Instant>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Who a call comes from, for operation ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Client {
    Cert([u8; 32]),
    Name(String),
    Anonymous,
}

fn client(peer: Option<&str>) -> Client {
    match (crate::server::conn_meta::current(), peer) {
        (Some(c), _) => Client::Cert(c.client_cert_sha256),
        (None, Some(p)) => Client::Name(p.to_string()),
        (None, None) => Client::Anonymous,
    }
}

/// Serve the interface (server start, `--fhe-custody`). The caller also selects the engine's replication profile.
pub fn enable() {
    SERVED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
fn disable() {
    SERVED.store(false, Ordering::SeqCst);
}

pub fn handles(interface: Option<&str>) -> bool {
    interface == Some(IFACE)
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GenerateKeyV1 {
    pub param_set: u32,
    pub replication_policy_id: OctetString,
    pub decrypt_policy_id: OctetString,
    pub label: OctetString,
    pub id: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DeriveKeyV1<'a> {
    pub base_key: Utf8StringRef<'a>,
    pub version: u32,
    pub kind: u32,
    pub key: u32,
    pub digit: u32,
    pub from_limb: u64,
    pub to_limb: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GetAttributeValueV1<'a> {
    pub object: Utf8StringRef<'a>,
    pub types: Vec<u32>,
}

/// One template entry of the answer; `value` is absent when the engine reports `CK_UNAVAILABLE_INFORMATION`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AttributeV1 {
    pub attr_type: u32,
    #[asn1(optional = "true")]
    pub value: Option<OctetString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DecryptInitV1<'a> {
    pub key: Utf8StringRef<'a>,
    pub recipient: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DecryptV1 {
    pub ciphertext: OctetString,
    /// The caller's buffer size (`*pulDataLen`); 0 = size query (`pData == NULL`).
    pub output_len: u64,
}

/// Dispatch one call. `peer` is the authenticated client identity (mTLS CN). Returns `(CK_RV, output)`; as in
/// PKCS#11, `C_GetAttributeValue` returns its template together with `CKR_ATTRIBUTE_SENSITIVE` or
/// `CKR_ATTRIBUTE_TYPE_INVALID`.
pub fn dispatch_as(engine_session: Result<u32, ()>, peer: Option<&str>, function: u32, input: &[u8]) -> (u32, Option<Vec<u8>>) {
    match call(engine_session, peer, function, input) {
        Ok((rv, out)) => (rv, Some(out)),
        Err(rv) => (rv, None),
    }
}

fn call(engine_session: Result<u32, ()>, peer: Option<&str>, function: u32, input: &[u8]) -> Result<(u32, Vec<u8>), u32> {
    if !SERVED.load(Ordering::SeqCst) || !repl::educational_profile_selected() {
        return Err(CKR_FUNCTION_NOT_SUPPORTED);
    }
    if function == 0 || function > 8 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if input.len() > MAX_INPUT {
        return Err(CKR_DATA_INVALID);
    }
    let is_admin_peer = peer == Some(ROLE_ADMIN_CN);
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let st = g.get_or_insert_with(|| State { ops: HashMap::new(), objects: HashMap::new() });
    expire(st);
    if function >= 7 {
        if !is_admin_peer {
            return Err(CKR_USER_TYPE_INVALID);
        }
        return admin(function, input).map(|o| (CKR_OK, o));
    }
    // User functions refuse the SO identity: the two roles never share a connection's authority.
    if is_admin_peer {
        return Err(CKR_USER_TYPE_INVALID);
    }
    let s = engine_session.map_err(|()| CKR_USER_NOT_LOGGED_IN)?;
    let me = client(peer);
    match function {
        1 => generate_key(s, input).map(|o| (CKR_OK, o)),
        2 => derive_key(st, s, input).map(|o| (CKR_OK, o)),
        3 => get_attribute_value(s, input),
        4 => destroy_object(st, s, input).map(|()| (CKR_OK, Vec::new())),
        5 => decrypt_init(st, s, &me, input).map(|()| (CKR_OK, Vec::new())),
        6 => decrypt(st, s, &me, input),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

/// Cancel abandoned decryptions and destroy forgotten public objects.
fn expire(st: &mut State) {
    st.ops.retain(|s, (_, t)| {
        let live = t.elapsed() < OP_TTL && softhsmrustv3::replication::fhe_custody::active(*s).is_some();
        if !live {
            softhsmrustv3::replication::fhe_custody::cancel(*s);
        }
        live
    });
    st.objects.retain(|(s, h), t| {
        let live = t.elapsed() < OBJECT_TTL;
        if !live {
            let _ = softhsmrustv3::ffi::C_DestroyObject(*s, *h);
        }
        live
    });
}

fn admin(function: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    let meta = super::engine_bridge::admin_context_meta(ROLE_ADMIN_CN, "kmip-fhe-bridge");
    match function {
        7 if input.is_empty() => so_call(meta, |h| repl::admin::issue_nonce(h).map(|n| n.to_vec())),
        8 if !input.is_empty() => {
            // Only the FHE operations go through this interface; the engine re-checks everything.
            let req: repl::admin::AdminSignedRequest = repl::asn1::decode_strict(input, repl::admin::MAX_ADMIN_REQUEST_DER)?;
            match req.tbs.operation()? {
                repl::admin::AdminOperation::EnrollFheDecryptPolicy { .. }
                | repl::admin::AdminOperation::EnrollFheRecipient { .. }
                | repl::admin::AdminOperation::DestroyFheSeed { .. } => {}
                _ => return Err(CKR_FUNCTION_NOT_SUPPORTED),
            }
            so_call(meta, |h| repl::admin::execute(h, input))
        }
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

fn ck(rv: u32) -> Result<(), u32> {
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

fn uid(input: &[u8]) -> Result<&[u8], u32> {
    if input.len() == 36 { Ok(input) } else { Err(CKR_ARGUMENTS_BAD) }
}

fn unique_id(s: u32, h: u32) -> Result<Vec<u8>, u32> {
    softhsmrustv3::native::get_attribute(s, h, CKA_UNIQUE_ID).ok_or(CKR_DEVICE_ERROR)
}

/// 1: `C_GenerateKey(CKM_PQCTODAY_FHE_KEY_GEN)` with a token template (`CKA_TOKEN`, optional `CKA_LABEL`/`CKA_ID`).
fn generate_key(s: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    let g: GenerateKeyV1 = repl::asn1::decode_strict(input, 4096)?;
    let (rp, dp) = (g.replication_policy_id.as_bytes(), g.decrypt_policy_id.as_bytes());
    let (label, id) = (g.label.as_bytes(), g.id.as_bytes());
    if rp.len() != 48 || dp.len() != 48 || label.len() > MAX_ATTR || id.len() > MAX_ATTR {
        return Err(CKR_DATA_INVALID);
    }
    // Mechanism parameter version 1: version, paramSet (CK_ULONGs), replication and decrypt policy IDs.
    let mut prm = Vec::with_capacity(2 * W + 96);
    prm.extend_from_slice(&1usize.to_ne_bytes());
    prm.extend_from_slice(&(g.param_set as usize).to_ne_bytes());
    prm.extend_from_slice(rp);
    prm.extend_from_slice(dp);
    let token = [1u8];
    let mut attrs: Vec<(u32, &[u8])> = vec![(CKA_TOKEN, &token)];
    if !label.is_empty() {
        attrs.push((CKA_LABEL, label));
    }
    if !id.is_empty() {
        attrs.push((CKA_ID, id));
    }
    let tmpl: Vec<usize> = attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect();
    let mut m = [CKM_PQCTODAY_FHE_KEY_GEN as usize, prm.as_ptr() as usize, prm.len()];
    let mut h = 0u32;
    ck(softhsmrustv3::ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h))?;
    unique_id(s, h)
}

/// 2: `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)`, parameter version 1 (TFHE, kind only) or 2 (CKKS pieces). The
/// new public session object is read with function 3 and destroyed with function 4.
fn derive_key(st: &mut State, s: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    let d: DeriveKeyV1 = repl::asn1::decode_strict(input, 256)?;
    let usz = |v: u64| usize::try_from(v).map_err(|_| CKR_DATA_INVALID);
    let p: Vec<usize> = match d.version {
        1 if (d.key, d.digit, d.from_limb, d.to_limb) == (0, 0, 0, 0) => vec![1, d.kind as usize],
        2 => vec![2, d.kind as usize, d.key as usize, d.digit as usize, usz(d.from_limb)?, usz(d.to_limb)?],
        _ => return Err(CKR_DATA_INVALID),
    };
    let base = by_uid(s, d.base_key.as_bytes())?;
    let mut m = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC as usize, p.as_ptr() as usize, p.len() * W];
    let mut h = 0u32;
    ck(softhsmrustv3::ffi::C_DeriveKey(s, m.as_mut_ptr() as *mut u8, base, std::ptr::null_mut(), 0, &mut h))?;
    st.objects.insert((s, h), Instant::now());
    unique_id(s, h)
}

/// 3: `C_GetAttributeValue`: size pass, then value pass; the engine's return code and the whole template come back,
/// with unavailable entries (`CK_UNAVAILABLE_INFORMATION`) left without a value.
fn get_attribute_value(s: u32, input: &[u8]) -> Result<(u32, Vec<u8>), u32> {
    let q: GetAttributeValueV1 = repl::asn1::decode_strict(input, 1024)?;
    if q.types.is_empty() || q.types.len() > MAX_ATTR_TYPES {
        return Err(CKR_DATA_INVALID);
    }
    let h = by_uid(s, q.object.as_bytes())?;
    let n = q.types.len();
    let mut t: Vec<usize> = q.types.iter().flat_map(|ty| [*ty as usize, 0, 0]).collect();
    let rv = softhsmrustv3::ffi::C_GetAttributeValue(s, h, t.as_mut_ptr() as *mut u8, n as u32);
    if !matches!(rv, CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID) {
        return Err(rv);
    }
    let mut total = 0usize;
    let mut bufs: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
    for i in 0..n {
        let len = t[3 * i + 2];
        if len == usize::MAX {
            bufs.push(None);
        } else {
            total = total.saturating_add(len);
            bufs.push(Some(vec![0u8; len]));
        }
    }
    if total > MAX_OUTPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    for (i, b) in bufs.iter_mut().enumerate() {
        if let Some(b) = b {
            t[3 * i + 1] = b.as_mut_ptr() as usize;
        }
    }
    let rv = softhsmrustv3::ffi::C_GetAttributeValue(s, h, t.as_mut_ptr() as *mut u8, n as u32);
    if !matches!(rv, CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID) {
        return Err(rv);
    }
    let mut out = Vec::with_capacity(n);
    for (i, b) in bufs.into_iter().enumerate() {
        let len = t[3 * i + 2];
        let value = match b {
            Some(mut v) if len != usize::MAX => {
                v.truncate(len);
                Some(OctetString::new(v).map_err(|_| CKR_DEVICE_ERROR)?)
            }
            _ => None,
        };
        out.push(AttributeV1 { attr_type: q.types[i], value });
    }
    Ok((rv, repl::asn1::to_der(&out)?))
}

/// 4: `C_DestroyObject`. The token applies `CKA_DESTROYABLE`: FHE seeds are not destroyable (`CKR_ACTION_PROHIBITED`),
/// derived public objects are.
fn destroy_object(st: &mut State, s: u32, input: &[u8]) -> Result<(), u32> {
    let h = by_uid(s, uid(input)?)?;
    ck(softhsmrustv3::ffi::C_DestroyObject(s, h))?;
    st.objects.remove(&(s, h));
    Ok(())
}

/// 5: `C_DecryptInit(CKM_PQCTODAY_FHE_DECRYPT)`: parameter version 1, recipient ID (48 zero bytes = owner release).
fn decrypt_init(st: &mut State, s: u32, me: &Client, input: &[u8]) -> Result<(), u32> {
    let d: DecryptInitV1 = repl::asn1::decode_strict(input, 256)?;
    if d.recipient.as_bytes().len() != 48 {
        return Err(CKR_DATA_INVALID);
    }
    // One operation per session (PKCS#11 §5.2): the same client gets CKR_OPERATION_ACTIVE as from the engine, and so
    // does every other client until the operation ends or expires.
    if st.ops.contains_key(&s) || softhsmrustv3::replication::fhe_custody::active(s).is_some() {
        return Err(CKR_OPERATION_ACTIVE);
    }
    let key = by_uid(s, d.key.as_bytes())?;
    let mut prm = vec![0u8; (W + 48).next_multiple_of(W)];
    prm[..W].copy_from_slice(&1usize.to_ne_bytes());
    prm[W..W + 48].copy_from_slice(d.recipient.as_bytes());
    let mut m = [CKM_PQCTODAY_FHE_DECRYPT as usize, prm.as_ptr() as usize, prm.len()];
    ck(softhsmrustv3::ffi::C_DecryptInit(s, m.as_mut_ptr() as *mut u8, key))?;
    st.ops.insert(s, (me.clone(), Instant::now()));
    Ok(())
}

/// 6: `C_Decrypt`, single part. `output_len` 0 is the size query (`pData == NULL`): the length comes back as a DER
/// INTEGER and the operation stays active. A buffer that is too small gets `CKR_BUFFER_TOO_SMALL` with the needed
/// length (DER INTEGER, as PKCS#11 sets `*pulDataLen`) and the operation stays active; every other outcome ends it
/// (PKCS#11 §5.2).
fn decrypt(st: &mut State, s: u32, me: &Client, input: &[u8]) -> Result<(u32, Vec<u8>), u32> {
    match st.ops.get(&s) {
        Some((owner, _)) if owner == me => {}
        _ => return Err(CKR_OPERATION_NOT_INITIALIZED),
    }
    let d: DecryptV1 = repl::asn1::decode_strict(input, MAX_INPUT)?;
    let ct = d.ciphertext.as_bytes();
    let out_len = usize::try_from(d.output_len).map_err(|_| CKR_DATA_INVALID)?;
    if out_len > MAX_OUTPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut n = 0u32;
    let r = if out_len == 0 {
        let rv = softhsmrustv3::ffi::C_Decrypt(s, ct.as_ptr() as *mut u8, ct.len() as u32, std::ptr::null_mut(), &mut n);
        ck(rv).and_then(|()| repl::asn1::to_der(&(n as u64))).map(|o| (CKR_OK, o))
    } else {
        let mut out = vec![0u8; out_len];
        n = out_len as u32;
        let rv = softhsmrustv3::ffi::C_Decrypt(s, ct.as_ptr() as *mut u8, ct.len() as u32, out.as_mut_ptr(), &mut n);
        match rv {
            CKR_OK => {
                out.truncate(n as usize);
                Ok((CKR_OK, out))
            }
            CKR_BUFFER_TOO_SMALL => repl::asn1::to_der(&(n as u64)).map(|o| (CKR_BUFFER_TOO_SMALL, o)),
            e => Err(e),
        }
    };
    if softhsmrustv3::replication::fhe_custody::active(s).is_none() {
        st.ops.remove(&s);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::engine_bridge::profile_lock;
    use der::Encode;

    fn on() {
        repl::select_educational_profile();
        enable();
    }

    fn off() {
        disable();
        repl::clear_profile();
    }

    fn rv(peer: Option<&str>, function: u32, input: &[u8]) -> u32 {
        dispatch_as(Ok(1), peer, function, input).0
    }

    /// True when the call got past the bridge's own routing and decoding (the engine, not initialised in these unit
    /// tests, answered), as opposed to being refused by the bridge.
    fn reached_the_engine(rv: u32) -> bool {
        !matches!(rv, CKR_ARGUMENTS_BAD | CKR_DATA_INVALID | CKR_FUNCTION_NOT_SUPPORTED | CKR_USER_TYPE_INVALID)
    }

    fn uid36() -> [u8; 36] {
        [b'a'; 36]
    }

    fn s36(u: &[u8; 36]) -> Utf8StringRef<'_> {
        Utf8StringRef::new(std::str::from_utf8(u).unwrap()).unwrap()
    }

    fn generate_der(rp_len: usize) -> Vec<u8> {
        GenerateKeyV1 {
            param_set: 0x8002,
            replication_policy_id: OctetString::new(vec![1u8; rp_len]).unwrap(),
            decrypt_policy_id: OctetString::new(vec![2u8; 48]).unwrap(),
            label: OctetString::new(b"seed".to_vec()).unwrap(),
            id: OctetString::new(Vec::new()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn derive_der(version: u32, key: u32) -> Vec<u8> {
        let u = uid36();
        DeriveKeyV1 { base_key: s36(&u), version, kind: 5, key, digit: 0, from_limb: 0, to_limb: 4 }.to_der().unwrap()
    }

    fn decrypt_init_der(recipient_len: usize) -> Vec<u8> {
        let u = uid36();
        DecryptInitV1 { key: s36(&u), recipient: OctetString::new(vec![0u8; recipient_len]).unwrap() }.to_der().unwrap()
    }

    #[test]
    fn interface_name_is_exact() {
        assert_eq!(IFACE, "PQCTODAY_FHE_1_0");
        assert!(handles(Some(IFACE)));
        assert!(!handles(None) && !handles(Some("PQCTODAY_FHE_1_")) && !handles(Some("PQCTODAY_FHE_2_0")) && !handles(Some("PQCTODAY_FHE_1_0 ")));
    }

    #[test]
    fn nothing_is_served_unless_enabled_and_the_profile_is_selected() {
        let _g = profile_lock();
        off();
        assert_eq!(rv(None, 4, &uid36()), CKR_FUNCTION_NOT_SUPPORTED);
        enable();
        assert_eq!(rv(None, 4, &uid36()), CKR_FUNCTION_NOT_SUPPORTED, "profile not selected");
        disable();
        repl::select_educational_profile();
        assert_eq!(rv(None, 4, &uid36()), CKR_FUNCTION_NOT_SUPPORTED, "interface not enabled");
        off();
    }

    #[test]
    fn function_values_are_one_based_and_bounded() {
        let _g = profile_lock();
        on();
        assert_eq!(rv(None, 0, &uid36()), CKR_ARGUMENTS_BAD);
        assert_eq!(rv(None, 9, &uid36()), CKR_ARGUMENTS_BAD);
        assert_eq!(rv(None, 4, &uid36()[..35]), CKR_ARGUMENTS_BAD, "a unique ID is 36 bytes");
        assert!(reached_the_engine(rv(None, 4, &uid36())));
        off();
    }

    #[test]
    fn roles_are_separated() {
        let _g = profile_lock();
        on();
        // SO functions refuse every identity but the security officer's.
        assert_eq!(rv(None, 7, b""), CKR_USER_TYPE_INVALID);
        assert_eq!(rv(Some("tenant-a"), 7, b""), CKR_USER_TYPE_INVALID);
        assert_eq!(rv(Some("fhe-admin"), 8, b"x"), CKR_USER_TYPE_INVALID);
        assert_eq!(ROLE_ADMIN_CN, "replication-admin");
        // User functions refuse the SO identity.
        assert_eq!(rv(Some(ROLE_ADMIN_CN), 4, &uid36()), CKR_USER_TYPE_INVALID);
        assert_eq!(rv(Some(ROLE_ADMIN_CN), 1, &generate_der(48)), CKR_USER_TYPE_INVALID);
        // Without an engine session the user functions stop before the engine.
        assert_eq!(dispatch_as(Err(()), None, 4, &uid36()).0, CKR_USER_NOT_LOGGED_IN);
        off();
    }

    #[test]
    fn inputs_are_strict_der() {
        let _g = profile_lock();
        on();
        assert!(reached_the_engine(rv(None, 1, &generate_der(48))));
        assert_eq!(rv(None, 1, &generate_der(47)), CKR_DATA_INVALID, "policy IDs are 48 bytes");
        let mut trailing = generate_der(48);
        trailing.push(0);
        assert_eq!(rv(None, 1, &trailing), CKR_DATA_INVALID);
        assert!(reached_the_engine(rv(None, 2, &derive_der(2, 0))));
        assert_eq!(rv(None, 2, &derive_der(3, 0)), CKR_DATA_INVALID, "parameter versions 1 and 2 only");
        assert_eq!(rv(None, 2, &derive_der(1, 7)), CKR_DATA_INVALID, "version 1 carries the kind only");
        assert!(reached_the_engine(rv(None, 5, &decrypt_init_der(48))));
        assert_eq!(rv(None, 5, &decrypt_init_der(32)), CKR_DATA_INVALID, "recipient IDs are 48 bytes");
        assert_eq!(rv(None, 3, b"junk"), CKR_DATA_INVALID);
        off();
    }

    #[test]
    fn decrypt_without_an_operation_of_ones_own_is_not_initialised() {
        let _g = profile_lock();
        on();
        let d = DecryptV1 { ciphertext: OctetString::new(vec![1u8; 8]).unwrap(), output_len: 0 }.to_der().unwrap();
        assert_eq!(rv(None, 6, &d), CKR_OPERATION_NOT_INITIALIZED);
        off();
    }

    /// The same bytes as the Python client's `tests/test_fhe.py` (`DERIVE_VECTOR`, `GENERATE_VECTOR`).
    #[test]
    fn wire_vectors_match_the_python_client() {
        let derive = format!("30380c24{}020102020105020103020100020100020104", "61".repeat(36));
        let generate = format!("307102030080020430{}0430{}0404736565640400", "01".repeat(48), "02".repeat(48));
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&derive_der(2, 3)), derive);
        assert_eq!(hex(&generate_der(48)), generate);
    }

    /// The mutants of `valid` (plan D02387 WP-A3, spec §10 gate 5): every proper prefix, 1..=8 appended bytes, every
    /// position XORed with 0x01, 0x80 and 0xff, and 2,000 seeded random rewrites (fixed-seed xorshift64*).
    fn mutants(valid: &[u8], seed: u64) -> Vec<Vec<u8>> {
        let mut x = seed | 1;
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        let mut out: Vec<Vec<u8>> = (0..valid.len()).map(|n| valid[..n].to_vec()).collect();
        for n in 1..=8 {
            let mut v = valid.to_vec();
            v.extend((0..n).map(|_| next() as u8));
            out.push(v);
        }
        for i in 0..valid.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut v = valid.to_vec();
                v[i] ^= mask;
                out.push(v);
            }
        }
        for _ in 0..2000 {
            let mut v = valid.to_vec();
            for _ in 0..1 + next() % 8 {
                let i = (next() % v.len() as u64) as usize;
                v[i] = next() as u8;
            }
            out.push(v);
        }
        out.retain(|m| m != valid);
        out
    }

    /// Parser robustness of every V1 input of the interface and of the admin request function 8 accepts (plan D02387
    /// WP-A3): for each mutant the strict decoder the bridge uses does not panic, and either refuses it or returns a
    /// value whose DER is the mutant itself; the bridge's own field checks (lengths, versions, function 8's operation
    /// filter) do not panic either. Decoder level only: these unit tests have no engine, and a mutant that decoded
    /// would otherwise reach whatever engine state another test left (the real-engine pass is
    /// `tests/fhe_custody_e2e.rs`).
    #[test]
    fn v1_inputs_survive_mutation() {
        macro_rules! strict {
            ($t:ty, $m:expr, $max:expr) => {
                repl::asn1::decode_strict::<$t>($m, $max).ok().map(|v| (v.to_der().unwrap(), v))
            };
        }
        let u = uid36();
        let get = GetAttributeValueV1 { object: s36(&u), types: vec![CKA_VALUE, 0x8000_0110] }.to_der().unwrap();
        let dec = DecryptV1 { ciphertext: OctetString::new(vec![7u8; 40]).unwrap(), output_len: 9 }.to_der().unwrap();
        let attrs = vec![AttributeV1 { attr_type: CKA_VALUE, value: Some(OctetString::new(vec![1, 2]).unwrap()) }, AttributeV1 { attr_type: 0x8000_0110, value: None }].to_der().unwrap();
        let cases: [(&str, Vec<u8>); 6] = [
            ("GenerateKeyV1", generate_der(48)),
            ("DeriveKeyV1", derive_der(2, 3)),
            ("GetAttributeValueV1", get),
            ("DecryptInitV1", decrypt_init_der(48)),
            ("DecryptV1", dec),
            ("AttributesV1", attrs),
        ];
        for (k, (name, valid)) in cases.iter().enumerate() {
            let mut accepted = 0;
            for m in mutants(valid, 0xa3_b000 + k as u64) {
                let r = std::panic::catch_unwind(|| -> Option<Vec<u8>> {
                    match k {
                        0 => strict!(GenerateKeyV1, &m, 4096).map(|(der, g)| {
                            let _ = g.replication_policy_id.as_bytes().len() == 48 && g.label.as_bytes().len() <= MAX_ATTR;
                            der
                        }),
                        1 => strict!(DeriveKeyV1, &m, 256).map(|(der, d)| {
                            let _ = (usize::try_from(d.from_limb), usize::try_from(d.to_limb), d.base_key.as_bytes().len());
                            der
                        }),
                        2 => strict!(GetAttributeValueV1, &m, 1024).map(|(der, _)| der),
                        3 => strict!(DecryptInitV1, &m, 256).map(|(der, _)| der),
                        4 => strict!(DecryptV1, &m, MAX_INPUT).map(|(der, d)| {
                            let _ = usize::try_from(d.output_len);
                            der
                        }),
                        _ => strict!(Vec<AttributeV1>, &m, 1024).map(|(der, _)| der),
                    }
                });
                match r {
                    Err(_) => panic!("{name}: a mutant of {} bytes panicked", m.len()),
                    Ok(Some(der)) => {
                        assert_eq!(der, m, "{name}: accepted mutant re-encodes differently");
                        accepted += 1;
                    }
                    Ok(None) => {}
                }
            }
            eprintln!("{name}: {accepted} mutants decoded as other valid values");
        }

        // Function 8's input: an AdminSignedRequest with each FHE operation, through the bridge's decoder and its
        // operation filter.
        let ops = [
            repl::admin::AdminOperation::EnrollFheDecryptPolicy { policy: vec![0x30, 0x03, 0x02, 0x01, 0x01] },
            repl::admin::AdminOperation::EnrollFheRecipient { chain: vec![vec![0x30, 0x00], vec![0x30, 0x01, 0x00]] },
            repl::admin::AdminOperation::DestroyFheSeed { lineage: [8u8; 32] },
        ];
        for (i, op) in ops.iter().enumerate() {
            let tbs = repl::admin_host::tbs_request(&[1u8; 32], &[2u8; 32], &[3u8; 32], 1, 1_790_000_000, op).unwrap();
            let req = repl::admin_host::signed_request(&tbs, &[0u8; 3309]).unwrap();
            for m in mutants(&req, 0xa3_b100 + i as u64) {
                let r = std::panic::catch_unwind(|| {
                    let d = repl::asn1::decode_strict::<repl::admin::AdminSignedRequest>(&m, repl::admin::MAX_ADMIN_REQUEST_DER).ok()?;
                    let _ = d.tbs.operation();
                    Some(d.to_der().unwrap())
                });
                match r {
                    Err(_) => panic!("AdminSignedRequest [{}]: a mutant of {} bytes panicked", 5 + i, m.len()),
                    Ok(Some(der)) => assert_eq!(der, m, "AdminSignedRequest [{}]: accepted mutant re-encodes differently", 5 + i),
                    Ok(None) => {}
                }
            }
        }
    }

    #[test]
    fn layouts_round_trip() {
        let g = generate_der(48);
        let back: GenerateKeyV1 = repl::asn1::decode_strict(&g, 4096).unwrap();
        assert_eq!(back.to_der().unwrap(), g);
        let d = derive_der(2, 3);
        let back: DeriveKeyV1 = repl::asn1::decode_strict(&d, 256).unwrap();
        assert_eq!((back.version, back.kind, back.key, back.to_limb), (2, 5, 3, 4));
        let attrs = vec![AttributeV1 { attr_type: CKA_VALUE, value: Some(OctetString::new(vec![1, 2]).unwrap()) }, AttributeV1 { attr_type: 0x8000_0110, value: None }];
        let der = attrs.to_der().unwrap();
        let back: Vec<AttributeV1> = repl::asn1::decode_strict(&der, 1024).unwrap();
        assert_eq!(back, attrs);
    }
}
