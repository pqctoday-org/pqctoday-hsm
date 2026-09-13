//! Behaviour event ring — one 8-byte record per crypto operation, written
//! into a shared-memory ring for an out-of-process consumer.
//!
//! This is the third runtime-gated evidence sink in this crate, next to
//! [`crate::oplog`] (`PQCEV` lines) and [`crate::authlog`] (`PQCAUTH` lines).
//! Those two are text for humans and scripts; this one is a fixed-width
//! binary record for a daemon that wants *every* operation at a cost the
//! crypto-serving processes cannot feel. The C++ engine writes the identical
//! record and ring (`src/lib/common/BehaviourRing.{h,cpp}`); the id tables
//! both use are generated from `behaviour/ids.json` (see [`ids`]).
//!
//! # The record (8 bytes, little-endian `u64`, byte 0 first)
//!
//! | byte | field     | meaning |
//! |------|-----------|---------|
//! | 0    | `src`     | which surface produced it (`SRC_*`) |
//! | 1    | `op`      | operation id in that surface's namespace (`OP_*`) |
//! | 2    | `alg`     | algorithm + parameter set (`ALG_*`), 0 = n/a |
//! | 3    | `result`  | outcome class (`RESULT_*`) |
//! | 4    | `client`  | 8-bit bucket of the caller identity, 0 = local / none |
//! | 5    | `size`    | ⌊log2(input bytes)⌋, 0 when 0 or unknown |
//! | 6    | `latency` | ⌊log2(µs)⌋, 0 when unknown |
//! | 7    | `dt`      | ⌊log2(µs since this process's previous record)⌋, 255 = first |
//!
//! Bucketed on purpose: fixed width, no key material, no labels, no full
//! identities — nothing a public dashboard could not show.
//!
//! # The ring file (`PQC_BEHAVIOUR_RING`, format v1)
//!
//! ```text
//! offset  size  field
//! 0       u32   magic  0x5242_5150 ("PQBR")
//! 4       u32   format version (1)
//! 8       u32   slot count (power of two; 65 536 by default)
//! 12      u32   slot bytes (16)
//! 16      u64   head — next record index, claimed with an atomic add
//! 24      u64   created, ms since the epoch
//! 32      u32   id-table version (ids::TABLE_VERSION)
//! …       —     reserved to 4096
//! 4096    …     slots: [u64 record][u64 seq], slot i at 4096 + 16·(i mod count)
//! ```
//!
//! Multi-producer, single-consumer. A producer claims an index with one
//! atomic `fetch_add` on `head`, stores the record, then stores `seq =
//! index + 1` with release ordering. A reader walks from its position to
//! `head`, accepting a slot only when its `seq` equals `index + 1`: a smaller
//! `seq` is a slot not yet written (wait briefly, then skip), a larger one is
//! a slot already lapped (count it lost). With `head - position > count` the
//! reader has been lapped by more than a ring and resumes at `head - count`.
//! Nothing is ever dropped at the producer: the ring overwrites, and loss is
//! the reader's to measure — this is a derived stream, the audit trail is
//! elsewhere.
//!
//! Same three constraints as `oplog`, for the same reasons: gated at runtime
//! (`enabled()` is one load when the variable is unset), `cfg`'d to a no-op
//! on every wasm target, and never on when a benchmark measures.

pub mod ids;
pub use ids::*;

/// Path of the ring file. Unset or empty ⇒ this sink is absent.
pub const ENV_VAR: &str = "PQC_BEHAVIOUR_RING";
/// Which PKCS#11 surface this process is (`p11-local` when unset —
/// sshd, strongSwan, the KMIP server's own bridge); the two remoting
/// services set `p11-remoting-grpc` / `p11-remoting-rest` in their units.
pub const SRC_ENV_VAR: &str = "PQC_BEHAVIOUR_SRC";

pub const MAGIC: u32 = 0x5242_5150;
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 4096;
pub const SLOT_BYTES: usize = 16;
pub const DEFAULT_SLOTS: u32 = 65_536;

/// One event, before bucketing has been applied to the two duration fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Record {
    pub src: u8,
    pub op: u8,
    pub alg: u8,
    pub result: u8,
    pub client: u8,
    pub size: u8,
    pub latency: u8,
    pub dt: u8,
}

impl Record {
    pub const fn new(src: u8, op: u8, alg: u8, result: u8) -> Self {
        Record {
            src,
            op,
            alg,
            result,
            client: 0,
            size: 0,
            latency: 0,
            dt: 0,
        }
    }
    pub const fn client(mut self, bucket: u8) -> Self {
        self.client = bucket;
        self
    }
    /// Bucket an input length into byte 5.
    pub const fn size_bytes(mut self, n: u64) -> Self {
        self.size = log2_bucket(n);
        self
    }
    /// Bucket a duration into byte 6.
    pub const fn latency_us(mut self, us: u64) -> Self {
        self.latency = log2_bucket(us);
        self
    }
    pub const fn to_u64(self) -> u64 {
        u64::from_le_bytes([
            self.src,
            self.op,
            self.alg,
            self.result,
            self.client,
            self.size,
            self.latency,
            self.dt,
        ])
    }
    pub const fn from_u64(v: u64) -> Self {
        let b = v.to_le_bytes();
        Record {
            src: b[0],
            op: b[1],
            alg: b[2],
            result: b[3],
            client: b[4],
            size: b[5],
            latency: b[6],
            dt: b[7],
        }
    }
}

/// ⌊log2(v)⌋ for `v ≥ 1`; 0 for `v = 0`. Never exceeds 63.
pub const fn log2_bucket(v: u64) -> u8 {
    if v == 0 {
        0
    } else {
        (63 - v.leading_zeros()) as u8
    }
}

/// `1 + (fnv1a32(identity) mod 255)`, or 0 for an empty identity — so 0 is
/// reserved for "local / no identity" and every real identity lands in 1..=255.
pub fn client_bucket(identity: &str) -> u8 {
    if identity.is_empty() {
        return 0;
    }
    let mut h: u32 = 0x811c_9dc5;
    for b in identity.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    1 + (h % 255) as u8
}

/// Microseconds since `t0`, or 0 when timing was not started (the sinks
/// were all off). Saturates rather than wraps.
pub fn elapsed_us(t0: Option<std::time::Instant>) -> u64 {
    t0.map(|t| u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(not(target_arch = "wasm32"))]
mod sink {
    use super::{
        FORMAT_VERSION, HEADER_BYTES, MAGIC, Record, SLOT_BYTES, TABLE_VERSION, log2_bucket,
    };
    use std::fs::OpenOptions;
    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    const OFF_MAGIC: usize = 0;
    const OFF_VERSION: usize = 4;
    const OFF_SLOTS: usize = 8;
    const OFF_SLOT_BYTES: usize = 12;
    const OFF_HEAD: usize = 16;
    const OFF_CREATED: usize = 24;
    const OFF_TABLE: usize = 32;

    /// One mapped ring. The global sink holds exactly one; tests open their
    /// own so several rings can coexist in one process.
    pub struct Ring {
        base: *mut u8,
        len: usize,
        mask: u64,
        last_ns: AtomicU64,
        epoch: Instant,
    }

    // SAFETY: every access to the mapping goes through atomics; the raw
    // pointer is only ever offset, never handed out.
    unsafe impl Send for Ring {}
    unsafe impl Sync for Ring {}

    impl Ring {
        /// Open (creating and initialising if absent) the ring at `path`
        /// with `slots` slots — a power of two. The first process to create
        /// the file initialises the header and publishes the magic last;
        /// later openers wait for it. A file of the wrong size or version is
        /// refused, never silently rewritten.
        pub fn open(path: &Path, slots: u32) -> io::Result<Ring> {
            if !slots.is_power_of_two() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "slot count must be a power of two",
                ));
            }
            let len = HEADER_BYTES + slots as usize * SLOT_BYTES;
            let (file, initialiser) = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o660)
                .open(path)
            {
                Ok(f) => (f, true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    (OpenOptions::new().read(true).write(true).open(path)?, false)
                }
                Err(e) => return Err(e),
            };
            if initialiser {
                file.set_len(len as u64)?;
            } else {
                let actual = file.metadata()?.len();
                if actual != len as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ring file is {actual} bytes, expected {len}"),
                    ));
                }
            }
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    std::os::unix::io::AsRawFd::as_raw_fd(&file),
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let ring = Ring {
                base: base as *mut u8,
                len,
                mask: (slots - 1) as u64,
                last_ns: AtomicU64::new(0),
                epoch: Instant::now(),
            };
            if initialiser {
                ring.u32_at(OFF_VERSION)
                    .store(FORMAT_VERSION, Ordering::Relaxed);
                ring.u32_at(OFF_SLOTS).store(slots, Ordering::Relaxed);
                ring.u32_at(OFF_SLOT_BYTES)
                    .store(SLOT_BYTES as u32, Ordering::Relaxed);
                ring.u32_at(OFF_TABLE)
                    .store(TABLE_VERSION, Ordering::Relaxed);
                ring.u64_at(OFF_HEAD).store(0, Ordering::Relaxed);
                let created = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                ring.u64_at(OFF_CREATED).store(created, Ordering::Relaxed);
                // Published last: a concurrent opener that sees the magic sees
                // everything before it.
                ring.u32_at(OFF_MAGIC).store(MAGIC, Ordering::Release);
            } else {
                // Bounded wait for the initialiser to publish the header.
                let mut waited = 0u32;
                while ring.u32_at(OFF_MAGIC).load(Ordering::Acquire) != MAGIC {
                    if waited >= 1000 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ring header never became valid",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_micros(100));
                    waited += 1;
                }
                let version = ring.u32_at(OFF_VERSION).load(Ordering::Relaxed);
                let count = ring.u32_at(OFF_SLOTS).load(Ordering::Relaxed);
                let sb = ring.u32_at(OFF_SLOT_BYTES).load(Ordering::Relaxed);
                if version != FORMAT_VERSION || count != slots || sb as usize != SLOT_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "ring header mismatch: version {version}, {count} slots of {sb} bytes"
                        ),
                    ));
                }
            }
            Ok(ring)
        }

        fn u32_at(&self, off: usize) -> &AtomicU32 {
            debug_assert!(off + 4 <= self.len && off % 4 == 0);
            // SAFETY: in-bounds, 4-aligned (page-aligned base), lives as long as the mapping.
            unsafe { &*(self.base.add(off) as *const AtomicU32) }
        }

        fn u64_at(&self, off: usize) -> &AtomicU64 {
            debug_assert!(off + 8 <= self.len && off % 8 == 0);
            // SAFETY: as above, 8-aligned.
            unsafe { &*(self.base.add(off) as *const AtomicU64) }
        }

        /// Next index to be claimed (equivalently, records written so far).
        pub fn head(&self) -> u64 {
            self.u64_at(OFF_HEAD).load(Ordering::Acquire)
        }

        pub fn slots(&self) -> u32 {
            (self.mask + 1) as u32
        }

        /// Write one record, filling its `dt` from this ring's own clock.
        pub fn write(&self, mut rec: Record) {
            let now = self.epoch.elapsed().as_nanos() as u64 + 1; // 0 = never
            let prev = self.last_ns.swap(now, Ordering::Relaxed);
            rec.dt = if prev == 0 {
                255
            } else {
                log2_bucket(now.saturating_sub(prev) / 1000)
            };
            let idx = self.u64_at(OFF_HEAD).fetch_add(1, Ordering::Relaxed);
            let slot = HEADER_BYTES + ((idx & self.mask) as usize) * SLOT_BYTES;
            self.u64_at(slot).store(rec.to_u64(), Ordering::Relaxed);
            self.u64_at(slot + 8).store(idx + 1, Ordering::Release);
        }
    }

    impl std::fmt::Debug for Ring {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Ring")
                .field("slots", &self.slots())
                .field("head", &self.head())
                .finish()
        }
    }

    impl Drop for Ring {
        fn drop(&mut self) {
            // SAFETY: base/len are exactly what mmap returned.
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.len);
            }
        }
    }

    static RING: OnceLock<Option<Ring>> = OnceLock::new();
    static P11_SRC: OnceLock<u8> = OnceLock::new();

    fn ring() -> &'static Option<Ring> {
        RING.get_or_init(|| {
            let spec = std::env::var(super::ENV_VAR).ok()?;
            if spec.is_empty() {
                return None;
            }
            match Ring::open(Path::new(&spec), super::DEFAULT_SLOTS) {
                Ok(r) => Some(r),
                Err(e) => {
                    // Visible, not silent: a process asked to feed the
                    // monitor and unable to must say so once.
                    eprintln!(
                        "pqc-behaviour: cannot open ring {spec}: {e}; behaviour ring disabled"
                    );
                    None
                }
            }
        })
    }

    pub fn enabled() -> bool {
        ring().is_some()
    }

    pub fn emit(rec: Record) {
        if let Some(r) = ring().as_ref() {
            r.write(rec);
        }
    }

    pub fn p11_src() -> u8 {
        *P11_SRC.get_or_init(|| {
            std::env::var(super::SRC_ENV_VAR)
                .ok()
                .and_then(|s| super::ids::src_from_name(&s))
                .unwrap_or(super::ids::SRC_P11_LOCAL)
        })
    }
}

#[cfg(target_arch = "wasm32")]
mod sink {
    // No shared memory with another process on any wasm target.
    pub fn enabled() -> bool {
        false
    }
    pub fn emit(_rec: super::Record) {}
    pub fn p11_src() -> u8 {
        super::ids::SRC_P11_LOCAL
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use sink::Ring;

/// True when `PQC_BEHAVIOUR_RING` named a ring this process could map.
#[inline]
pub fn enabled() -> bool {
    sink::enabled()
}

/// Append one record. Best-effort, never blocks, never panics; a no-op
/// when the ring is absent. `rec.dt` is overwritten by the writer.
#[inline]
pub fn emit(rec: Record) {
    sink::emit(rec)
}

/// The `src` byte for this process's PKCS#11 records (`PQC_BEHAVIOUR_SRC`).
#[inline]
pub fn p11_src() -> u8 {
    sink::p11_src()
}

/// Build the record for one PKCS#11 entry point in this process.
#[inline]
pub fn p11(op: u8, alg: u8, rv: u32, size_bytes: u64, latency_us: u64) -> Record {
    Record::new(p11_src(), op, alg, result_from_ckr(rv))
        .size_bytes(size_bytes)
        .latency_us(latency_us)
}

/// [`p11`] for an entry point whose algorithm is the (mechanism, key's
/// `CKA_PARAMETER_SET`) pair. `mech == None` (the caller passed no mechanism)
/// records `ALG_NONE`; mechanism 0 is a real mechanism
/// (`CKM_RSA_PKCS_KEY_PAIR_GEN`), which is why this is an `Option`.
/// Only ever called behind [`enabled()`]: the parameter-set lookup is one
/// object-store read, which is nothing next to the operation but is not free.
#[inline]
pub fn p11_with_key(
    op: u8,
    mech: Option<u32>,
    h_key: u32,
    rv: u32,
    size_bytes: u64,
    latency_us: u64,
) -> Record {
    let alg = match mech {
        Some(m) => alg_from_ckm(m, crate::state::get_object_param_set(h_key)),
        None => ALG_NONE,
    };
    p11(op, alg, rv, size_bytes, latency_us)
}

/// What a reader sees: the header fields and every record still present,
/// oldest first, each with its index. Slots whose `seq` does not match are
/// skipped; `lost` counts indices that were overwritten before this read.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default)]
pub struct Snapshot {
    pub version: u32,
    pub slots: u32,
    pub head: u64,
    pub table_version: u32,
    pub lost: u64,
    pub records: Vec<(u64, Record)>,
}

/// Read a ring file in one pass (test and tooling helper; the appliance
/// daemon keeps its own incremental reader). Not a producer: opens read-only.
#[cfg(not(target_arch = "wasm32"))]
pub fn read_all(path: &std::path::Path) -> std::io::Result<Snapshot> {
    use std::io::{Error, ErrorKind};
    let bytes = std::fs::read(path)?;
    if bytes.len() < HEADER_BYTES {
        return Err(Error::new(ErrorKind::InvalidData, "short ring header"));
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    if u32_at(0) != MAGIC {
        return Err(Error::new(ErrorKind::InvalidData, "bad ring magic"));
    }
    let version = u32_at(4);
    let slots = u32_at(8);
    let slot_bytes = u32_at(12) as usize;
    let head = u64_at(16);
    let table_version = u32_at(32);
    if slot_bytes != SLOT_BYTES || !slots.is_power_of_two() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported ring geometry",
        ));
    }
    if bytes.len() < HEADER_BYTES + slots as usize * SLOT_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "ring file shorter than its header claims",
        ));
    }
    let start = head.saturating_sub(slots as u64);
    let mut records = Vec::with_capacity((head - start) as usize);
    for i in start..head {
        let off = HEADER_BYTES + ((i & (slots as u64 - 1)) as usize) * SLOT_BYTES;
        if u64_at(off + 8) == i + 1 {
            records.push((i, Record::from_u64(u64_at(off))));
        }
    }
    Ok(Snapshot {
        version,
        slots,
        head,
        table_version,
        lost: start,
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_bucket_is_floor_log2_with_zero_for_zero() {
        assert_eq!(log2_bucket(0), 0);
        assert_eq!(log2_bucket(1), 0);
        assert_eq!(log2_bucket(2), 1);
        assert_eq!(log2_bucket(3), 1);
        assert_eq!(log2_bucket(1024), 10);
        assert_eq!(log2_bucket(1500), 10);
        assert_eq!(log2_bucket(u64::MAX), 63);
    }

    #[test]
    fn client_bucket_reserves_zero_for_no_identity() {
        assert_eq!(client_bucket(""), 0);
        for id in ["cn=learner-1", "10.0.0.7:51234", "x"] {
            let b = client_bucket(id);
            assert!(b >= 1, "{id} bucketed to 0");
            assert_eq!(b, client_bucket(id), "not deterministic for {id}");
        }
    }

    #[test]
    fn record_round_trips_through_u64_with_src_in_byte_zero() {
        let r = Record::new(SRC_P11_LOCAL, OP_PKCS11_C_SIGN, ALG_ML_DSA_65, RESULT_OK)
            .client(9)
            .size_bytes(32)
            .latency_us(1500);
        let v = r.to_u64();
        assert_eq!(v & 0xff, SRC_P11_LOCAL as u64, "byte 0 must be src");
        assert_eq!(Record::from_u64(v), r);
    }

    #[test]
    fn golden_vectors_encode_exactly() {
        // The same vectors are asserted by the C++ engine's BehaviourRingTests,
        // which is what makes the two writers provably interchangeable.
        for &(src, op, alg, result, client, size, lat, dt, expected) in VECTORS {
            let mut r = Record::new(src, op, alg, result)
                .client(client)
                .size_bytes(size)
                .latency_us(lat);
            r.dt = if dt < 0 { 255 } else { log2_bucket(dt as u64) };
            assert_eq!(r.to_u64(), expected, "vector {src}/{op}/{alg}/{result}");
        }
    }

    #[test]
    fn id_tables_resolve_known_names_and_reject_unknown_ones() {
        assert_eq!(op_kmip("Sign"), 33);
        assert_eq!(op_kmip("NoSuchOp"), 0);
        assert_eq!(op_pkcs11("C_GenerateKeyPair"), OP_PKCS11_C_GENERATEKEYPAIR);
        assert_eq!(alg_from_name("ML-KEM-768"), ALG_ML_KEM_768);
        assert_eq!(alg_from_name(""), ALG_NONE);
        assert_eq!(alg_from_name("Kyber"), ALG_OTHER);
        assert_eq!(alg_from_ckm(crate::constants::CKM_ML_DSA, 2), ALG_ML_DSA_65);
        assert_eq!(
            alg_from_ckm(crate::constants::CKM_ML_DSA_KEY_PAIR_GEN, 3),
            ALG_ML_DSA_87
        );
        assert_eq!(alg_from_ckm(crate::constants::CKM_EDDSA, 0), ALG_EDDSA);
        assert_eq!(
            alg_from_ckm(crate::constants::CKM_RSA_PKCS_PSS, 7),
            ALG_RSA,
            "any param set"
        );
        assert_eq!(alg_from_ckm(0xdead_beef, 0), ALG_OTHER);
        assert_eq!(result_from_ckr(crate::constants::CKR_OK), RESULT_OK);
        assert_eq!(
            result_from_ckr(crate::constants::CKR_USER_NOT_LOGGED_IN),
            RESULT_AUTH_FAIL
        );
        assert_eq!(
            result_from_ckr(crate::constants::CKR_FUNCTION_FAILED),
            RESULT_INTERNAL_ERROR
        );
        assert_eq!(
            result_from_ckr(crate::constants::CKR_MECHANISM_INVALID),
            RESULT_CALLER_ERROR
        );
        assert_eq!(
            result_from_ckr(crate::constants::CKR_SIGNATURE_INVALID),
            RESULT_CALLER_ERROR
        );
        assert_eq!(result_from_kmip_reason(None), RESULT_OK);
        assert_eq!(
            result_from_kmip_reason(Some("PermissionDenied")),
            RESULT_POLICY_DENY
        );
        assert_eq!(
            result_from_kmip_reason(Some("CryptographicFailure")),
            RESULT_INTERNAL_ERROR
        );
        assert_eq!(
            result_from_kmip_reason(Some("ItemNotFound")),
            RESULT_CALLER_ERROR
        );
        assert_eq!(result_from_http_status(200), RESULT_OK);
        assert_eq!(result_from_http_status(403), RESULT_AUTH_FAIL);
        assert_eq!(result_from_http_status(404), RESULT_CALLER_ERROR);
        assert_eq!(result_from_http_status(500), RESULT_INTERNAL_ERROR);
    }

    #[test]
    fn generated_tables_match_ids_json() {
        // Drift guard: the checked-in generated files must be what gen.py
        // produces from ids.json right now.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let status = std::process::Command::new("python3")
            .arg(root.join("behaviour/gen.py"))
            .arg("--check")
            .status()
            .expect("python3 available");
        assert!(
            status.success(),
            "rust/src/behaviour/ids.rs or src/lib/common/BehaviourIds.h is stale — run python3 behaviour/gen.py"
        );
    }

    fn temp_ring(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pqc-behaviour-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("behaviour.ring")
    }

    #[test]
    fn ring_initialises_writes_and_reads_back_in_order() {
        let path = temp_ring("basic");
        let ring = Ring::open(&path, 16).expect("open");
        assert_eq!(ring.head(), 0);
        for i in 0..5u8 {
            ring.write(Record::new(SRC_P11_LOCAL, i, 0, RESULT_OK));
        }
        let snap = read_all(&path).expect("read");
        assert_eq!(snap.version, FORMAT_VERSION);
        assert_eq!(snap.slots, 16);
        assert_eq!(snap.table_version, TABLE_VERSION);
        assert_eq!(snap.head, 5);
        assert_eq!(snap.lost, 0);
        let ops: Vec<u8> = snap.records.iter().map(|(_, r)| r.op).collect();
        assert_eq!(ops, vec![0, 1, 2, 3, 4]);
        assert_eq!(snap.records[0].1.dt, 255, "first record has no predecessor");
        assert!(
            snap.records[1].1.dt < 255,
            "second record carries a real gap"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (HEADER_BYTES + 16 * SLOT_BYTES) as u64
        );
    }

    #[test]
    fn ring_wraps_and_the_reader_reports_the_loss() {
        let path = temp_ring("wrap");
        let ring = Ring::open(&path, 8).expect("open");
        for i in 0..20u8 {
            ring.write(Record::new(SRC_P11_LOCAL, i, 0, RESULT_OK));
        }
        let snap = read_all(&path).expect("read");
        assert_eq!(snap.head, 20);
        assert_eq!(snap.lost, 12, "20 written into 8 slots ⇒ 12 overwritten");
        let ops: Vec<u8> = snap.records.iter().map(|(_, r)| r.op).collect();
        assert_eq!(ops, (12..20).collect::<Vec<u8>>());
        let idx: Vec<u64> = snap.records.iter().map(|(i, _)| *i).collect();
        assert_eq!(idx, (12..20).collect::<Vec<u64>>());
    }

    #[test]
    fn second_opener_joins_an_existing_ring_and_shares_its_head() {
        let path = temp_ring("join");
        let a = Ring::open(&path, 16).expect("open a");
        a.write(Record::new(SRC_P11_LOCAL, 1, 0, RESULT_OK));
        let b = Ring::open(&path, 16).expect("open b");
        assert_eq!(b.head(), 1, "b sees a's write");
        b.write(Record::new(SRC_P11_REMOTING_GRPC, 2, 0, RESULT_OK));
        assert_eq!(a.head(), 2, "a sees b's write");
        let snap = read_all(&path).unwrap();
        let srcs: Vec<u8> = snap.records.iter().map(|(_, r)| r.src).collect();
        assert_eq!(srcs, vec![SRC_P11_LOCAL, SRC_P11_REMOTING_GRPC]);
    }

    #[test]
    fn an_existing_file_of_the_wrong_geometry_is_refused_not_rewritten() {
        let path = temp_ring("geometry");
        let _a = Ring::open(&path, 16).expect("open a");
        let err = Ring::open(&path, 32).expect_err("different slot count must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(read_all(&path).unwrap().slots, 16, "file untouched");
        let bogus = temp_ring("bogus");
        std::fs::write(&bogus, b"not a ring").unwrap();
        assert!(Ring::open(&bogus, 16).is_err());
        assert_eq!(
            std::fs::read(&bogus).unwrap(),
            b"not a ring",
            "file untouched"
        );
    }

    #[test]
    fn concurrent_writers_never_lose_or_duplicate_an_index() {
        let path = temp_ring("threads");
        let ring = std::sync::Arc::new(Ring::open(&path, 1024).expect("open"));
        let threads: Vec<_> = (0..8u8)
            .map(|t| {
                let ring = ring.clone();
                std::thread::spawn(move || {
                    for i in 0..100u8 {
                        ring.write(Record::new(t + 1, i, 0, RESULT_OK));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let snap = read_all(&path).unwrap();
        assert_eq!(snap.head, 800);
        assert_eq!(snap.records.len(), 800, "every claimed index was published");
        let mut per_src = [0u32; 9];
        for (_, r) in &snap.records {
            per_src[r.src as usize] += 1;
        }
        assert_eq!(&per_src[1..], &[100; 8]);
    }
}
