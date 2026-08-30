//! `ck_param` — a typed, ABI-derived reader for caller-supplied PKCS#11
//! mechanism-parameter structs.
//!
//! ## The bug class this exists to make unrepresentable
//!
//! `CK_ULONG` is `unsigned long`: **8 bytes on an LP64 native build, 4 bytes
//! on wasm32/emscripten**. Every mechanism-parameter struct in `pkcs11t.h` is
//! a sequence of `CK_ULONG`s, pointers and `CK_BBOOL`s, so *every* field
//! offset in *every* one of them changes with the target. Code that writes a
//! literal `4`, or reads a `CK_ULONG` through a `*const u32`, is correct in
//! the browser and wrong natively — and the browser is the only target most
//! tests exercise, so it survives.
//!
//! Four instances were found and fixed by hand in August 2026:
//!
//! 1. `CK_AES_CTR_PARAMS.cb` taken at a hardcoded offset 4 (`844ed27`) — the
//!    counter block four bytes early, so **every AES-CTR ciphertext the
//!    native library ever produced was non-interoperable**.
//! 2. `CK_EDDSA_PARAMS.phFlag` read as a `u32` over a one-byte `CK_BBOOL`
//!    (`7f66aae`) — three bytes of the caller's uninitialised padding decided
//!    whether the signature was pure Ed25519 or Ed25519ph. Wrong on **every**
//!    target, wasm32 included.
//! 3. Vendor KMAC params read as three `u32`s where the first is a
//!    `CK_BYTE_PTR` — truncated to its low half **and then dereferenced**.
//! 4. `CK_MAC_GENERAL_PARAMS` (a bare `CK_ULONG`) read as a `u32`.
//!
//! Instances 2–4 each appeared three times, copy-pasted across
//! `C_SignInit` / `C_VerifyInit` / `C_MessageSignInit`.
//!
//! ## How this module removes it
//!
//! A parameter struct is **declared once** as its field sequence, exactly as
//! `pkcs11t.h` spells it. Offsets are then *computed* by the C struct-layout
//! rules from that declaration and the target's word width. There is no
//! numeric offset anywhere in a call site to get wrong:
//!
//! ```text
//! let r = ParamReader::new(p_param, len, &eddsa::LAYOUT, eddsa::FIELD_COUNT)?;
//! let ph = r.bbool(eddsa::PH_FLAG);     // one byte, at the ABI's offset
//! let ctx = r.buffer(eddsa::P_CONTEXT_DATA, eddsa::UL_CONTEXT_DATA_LEN);
//! ```
//!
//! ## Why a declared field *sequence* and not a bare field index
//!
//! The obvious shape — `reader.ulong(i)` where `i` is a "logical field index"
//! and the offset is `i * size_of::<usize>()` — is wrong, and wrong in a way
//! that is easy to miss. `CK_HKDF_PARAMS` opens with **two adjacent
//! `CK_BBOOL`s** (`bExtract` at byte 0, `bExpand` at byte 1, then
//! `prfHashMechanism` at the *first* word offset). Under an index-times-word
//! model `bExpand` would be read at offset 4/8 — i.e. from
//! `prfHashMechanism`. `CK_SP800_108_DKM_LENGTH_FORMAT` is the same story
//! with the `CK_BBOOL` in the middle. So the reader walks the real field
//! list, aligning and padding as a C compiler does; a struct with packed
//! `CK_BBOOL`s comes out right for free, and the caller never does
//! arithmetic.
//!
//! ## Correct on both ABIs, and pinned by tests
//!
//! `offset_at` / `size_at` take the word width as a parameter, so the tests
//! evaluate **both** ABIs on one host and compare against numbers taken from
//! a C compiler applied to the vendored `src/lib/pkcs11/pkcs11t.h`
//! (`offsetof` on LP64; `_Static_assert` on i386/i686/armv7 for ILP32).
//! A future edit cannot regress one target silently.

#![allow(dead_code)]

use core::marker::PhantomData;

/// Width of `CK_ULONG` and of a data pointer on this target.
pub const WORD: usize = core::mem::size_of::<usize>();

// The whole engine (and `ck_abi`'s narrowing shims) equate `CK_ULONG` with
// `usize`. That holds on LP64 and on every ILP32 target, but NOT on LLP64
// Windows, where `unsigned long` is 4 bytes and a pointer is 8. Fail at
// compile time rather than silently mis-lay-out every struct in this file.
#[cfg(not(target_arch = "wasm32"))]
const _: () = assert!(
    core::mem::size_of::<usize>() == core::mem::size_of::<core::ffi::c_ulong>(),
    "ck_param assumes CK_ULONG (`unsigned long`) and a data pointer have the \
     same width. Port ck_param before targeting LLP64."
);

/// A field of a caller-supplied PKCS#11 parameter struct, exactly as
/// `pkcs11t.h` declares it.
///
/// The point of the distinction between `Ulong`/`Ptr` (which are the same
/// width) and `Bbool` is that a `CK_BBOOL` is **one byte with alignment 1** —
/// instance 2 above is precisely the case where reading four bytes is wrong
/// on every platform, not merely on LP64.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum F {
    /// `CK_ULONG` and every typedef of it (`CK_MECHANISM_TYPE`, `CK_FLAGS`,
    /// `CK_OBJECT_HANDLE`, `CK_EC_KDF_TYPE`, `CK_HEDGE_TYPE`, …).
    Ulong,
    /// Any data pointer (`CK_BYTE_PTR`, `CK_VOID_PTR`, `CK_UTF8CHAR_PTR`, …).
    Ptr,
    /// `CK_BBOOL` — **one** byte, alignment 1.
    Bbool,
    /// `CK_BYTE arr[N]` — N bytes, alignment 1.
    Bytes(usize),
}

/// Size of one field under an ABI whose `CK_ULONG`/pointer width is `word`.
pub const fn field_size(f: F, word: usize) -> usize {
    match f {
        F::Ulong | F::Ptr => word,
        F::Bbool => 1,
        F::Bytes(n) => n,
    }
}

/// Alignment of one field under an ABI whose `CK_ULONG`/pointer width is
/// `word`. Byte-typed fields have alignment 1 — this is what makes a packed
/// `CK_BBOOL` pair come out at bytes 0 and 1.
pub const fn field_align(f: F, word: usize) -> usize {
    match f {
        F::Ulong | F::Ptr => word,
        F::Bbool | F::Bytes(_) => 1,
    }
}

const fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Byte offset of field `i` under the C struct-layout rules: each field is
/// placed at the next offset satisfying its own alignment.
pub const fn offset_at(fields: &[F], i: usize, word: usize) -> usize {
    assert!(i < fields.len(), "ck_param: field index out of range");
    let mut cur = 0usize;
    let mut k = 0usize;
    while k < i {
        cur = align_up(cur, field_align(fields[k], word)) + field_size(fields[k], word);
        k += 1;
    }
    align_up(cur, field_align(fields[i], word))
}

/// Byte offset one past the end of field `i` — i.e. the smallest
/// `ulParameterLen` that makes field `i` fully readable.
pub const fn end_at(fields: &[F], i: usize, word: usize) -> usize {
    offset_at(fields, i, word) + field_size(fields[i], word)
}

/// `sizeof` the whole struct, including trailing padding to the struct's own
/// alignment (the maximum of its fields').
pub const fn size_at(fields: &[F], word: usize) -> usize {
    let mut cur = 0usize;
    let mut max_align = 1usize;
    let mut k = 0usize;
    while k < fields.len() {
        let a = field_align(fields[k], word);
        if a > max_align {
            max_align = a;
        }
        cur = align_up(cur, a) + field_size(fields[k], word);
        k += 1;
    }
    align_up(cur, max_align)
}

/// A declared parameter-struct layout.
#[derive(Clone, Copy, Debug)]
pub struct Struct {
    /// The `pkcs11t.h` type name, used in assertion messages.
    pub name: &'static str,
    /// The field sequence, in declaration order.
    pub fields: &'static [F],
}

impl Struct {
    /// Byte offset of field `i` on **this** target.
    pub const fn offset(&self, i: usize) -> usize {
        offset_at(self.fields, i, WORD)
    }
    /// One past the end of field `i` on this target.
    pub const fn end(&self, i: usize) -> usize {
        end_at(self.fields, i, WORD)
    }
    /// `sizeof` on this target.
    pub const fn size(&self) -> usize {
        size_at(self.fields, WORD)
    }
    /// Smallest `ulParameterLen` that covers the first `n` fields. `n == 0`
    /// is 0 bytes (a caller may legitimately supply nothing).
    pub const fn min_len(&self, n: usize) -> usize {
        if n == 0 { 0 } else { end_at(self.fields, n - 1, WORD) }
    }
}

/// Why a parameter could not be read. Kept distinct from a `CK_RV` because
/// the engine's existing call sites do not agree on which code an *absent*
/// parameter deserves (`CKR_ARGUMENTS_BAD` in the derive paths,
/// `CKR_MECHANISM_PARAM_INVALID` in the sign paths, "use the documented
/// default" in several others). The reader reports the fact; the call site
/// keeps its own, unchanged, spec-driven mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParamErr {
    /// `pParameter` was NULL (or `ulParameterLen` was 0).
    Absent,
    /// `pParameter` is non-NULL but `ulParameterLen` does not cover the
    /// fields this mechanism needs. **This is the `require_len` guard**: a
    /// short buffer fails here instead of being over-read.
    TooShort,
}

/// A bounds-checked view over one caller-supplied parameter struct.
///
/// Construction performs the single length check (`require_len`); every
/// accessor then re-checks its own field against the caller's real
/// `ulParameterLen` as a backstop, and asserts that the field's declared kind
/// matches the accessor used. Both checks compare against constants and
/// compile out to almost nothing; neither can be reached by caller data once
/// `new` has succeeded for the fields a mechanism reads, so a fired assertion
/// means an engine bug, never a malformed call.
#[derive(Debug)]
pub struct ParamReader<'a> {
    base: *const u8,
    len: usize,
    layout: &'static Struct,
    _life: PhantomData<&'a [u8]>,
}

impl<'a> ParamReader<'a> {
    /// Bounds-check once and hand back a reader.
    ///
    /// `min_fields` is how many leading fields this mechanism actually reads
    /// — not necessarily the whole struct, because several parameter structs
    /// have optional tails (`CK_SP800_108_KDF_PARAMS`'s additional-derived-key
    /// fields, for one) that this engine does not implement.
    ///
    /// # Safety
    /// `p` must either be NULL or point to `len` readable bytes that outlive
    /// `'a`.
    pub unsafe fn new(
        p: *const u8,
        len: usize,
        layout: &'static Struct,
        min_fields: usize,
    ) -> Result<Self, ParamErr> {
        if p.is_null() || len == 0 {
            return Err(ParamErr::Absent);
        }
        if len < layout.min_len(min_fields) {
            return Err(ParamErr::TooShort);
        }
        Ok(ParamReader { base: p, len, layout, _life: PhantomData })
    }

    /// Like [`new`](Self::new), but an absent parameter is `Ok(None)` rather
    /// than an error — for the mechanisms whose parameter is optional and
    /// whose spec text supplies a default. A *present but short* parameter is
    /// still `Err(TooShort)`: "the caller supplied nothing" and "the caller
    /// supplied a struct from a different ABI" must not be conflated.
    ///
    /// # Safety
    /// As [`new`](Self::new).
    pub unsafe fn optional(
        p: *const u8,
        len: usize,
        layout: &'static Struct,
        min_fields: usize,
    ) -> Result<Option<Self>, ParamErr> {
        match unsafe { Self::new(p, len, layout, min_fields) } {
            Ok(r) => Ok(Some(r)),
            Err(ParamErr::Absent) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The layout this reader was built against.
    pub fn layout(&self) -> &'static Struct {
        self.layout
    }

    /// The caller's `ulParameterLen`.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Does the caller's buffer cover the first `n` fields?
    ///
    /// For the handful of structs the engine reads progressively (OAEP: a
    /// `hashAlg`-only prefix is meaningful, the label fields are optional).
    pub fn covers(&self, n: usize) -> bool {
        self.len >= self.layout.min_len(n)
    }

    /// Explicit form of the construction-time guard, for a second, larger
    /// prefix discovered later in a parse.
    pub fn require_len(&self, n: usize) -> Result<(), ParamErr> {
        if self.covers(n) { Ok(()) } else { Err(ParamErr::TooShort) }
    }

    #[inline]
    fn field_ptr(&self, i: usize, want: F) -> *const u8 {
        let f = self.layout.fields[i];
        assert!(
            core::mem::discriminant(&f) == core::mem::discriminant(&want),
            "ck_param: {}[{}] is {:?}, read as {:?}",
            self.layout.name,
            i,
            f,
            want
        );
        let end = self.layout.end(i);
        assert!(
            self.len >= end,
            "ck_param: {}[{}] needs {} bytes, caller supplied {}",
            self.layout.name,
            i,
            end,
            self.len
        );
        unsafe { self.base.add(self.layout.offset(i)) }
    }

    /// A `CK_ULONG`-typed field, at the target's native width.
    ///
    /// # Safety
    /// The reader's construction contract.
    pub unsafe fn ulong(&self, i: usize) -> usize {
        unsafe { core::ptr::read_unaligned(self.field_ptr(i, F::Ulong) as *const usize) }
    }

    /// A `CK_ULONG`-typed field truncated to the engine's internal 32-bit
    /// width. Separate from [`ulong`](Self::ulong) so that "I am deliberately
    /// narrowing a mechanism/parameter-set code" is visible at the call site.
    ///
    /// # Safety
    /// As [`ulong`](Self::ulong).
    pub unsafe fn ulong32(&self, i: usize) -> u32 {
        unsafe { self.ulong(i) as u32 }
    }

    /// A pointer-typed field, at the target's native width.
    ///
    /// # Safety
    /// As [`ulong`](Self::ulong).
    pub unsafe fn ptr(&self, i: usize) -> *const u8 {
        unsafe {
            core::ptr::read_unaligned(self.field_ptr(i, F::Ptr) as *const usize) as *const u8
        }
    }

    /// A `CK_BBOOL` field. Reads **exactly one byte** — see instance 2 in the
    /// module docs. `CK_FALSE` is 0; the spec makes every non-zero value
    /// true.
    ///
    /// # Safety
    /// As [`ulong`](Self::ulong).
    pub unsafe fn bbool(&self, i: usize) -> bool {
        unsafe { core::ptr::read_unaligned(self.field_ptr(i, F::Bbool)) != 0 }
    }

    /// A `CK_BYTE arr[N]` field, borrowed in place. The length comes from the
    /// declaration, not from the call site.
    ///
    /// # Safety
    /// As [`ulong`](Self::ulong).
    pub unsafe fn bytes(&self, i: usize) -> &'a [u8] {
        let n = match self.layout.fields[i] {
            F::Bytes(n) => n,
            other => panic!(
                "ck_param: {}[{}] is {:?}, read as a byte array",
                self.layout.name, i, other
            ),
        };
        unsafe { core::slice::from_raw_parts(self.field_ptr(i, F::Bytes(n)), n) }
    }

    /// The pointer-plus-length idiom every one of these structs uses
    /// (`pSalt`/`ulSaltLen`, `pAAD`/`ulAADLen`, `pContext`/`ulContextLen`, …).
    /// A NULL pointer or a zero length yields an empty slice, which is what
    /// each spec's "no data supplied" case means.
    ///
    /// # Safety
    /// The reader's contract, plus: the caller's `p`/`len` pair must describe
    /// readable memory. That is the caller's assertion to the engine and
    /// cannot be checked here — but note that reading the *pair* at the right
    /// widths, which is what this method guarantees, is exactly what stops a
    /// truncated pointer from being dereferenced (instance 3).
    pub unsafe fn buffer(&self, ptr_field: usize, len_field: usize) -> &'a [u8] {
        let p = unsafe { self.ptr(ptr_field) };
        let n = unsafe { self.ulong(len_field) };
        if p.is_null() || n == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(p, n) }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Declared layouts
//
// Each of these is a transcription of the struct in
// `src/lib/pkcs11/pkcs11t.h` (kept in sync with the OASIS normative header
// per CLAUDE.md). Field-name constants are generated alongside so a call site
// names the field instead of counting.
// ─────────────────────────────────────────────────────────────────────────

macro_rules! ck_struct {
    ($(#[$m:meta])* $modname:ident, $cname:literal, { $($field:ident : $kind:expr),+ $(,)? }) => {
        $(#[$m])*
        pub mod $modname {
            #[allow(unused_imports)]
            use super::{F, Struct};
            /// The declared layout, in `pkcs11t.h` order.
            pub static LAYOUT: Struct = Struct { name: $cname, fields: &[$($kind),+] };
            ck_struct!(@idx 0usize; $($field)+);
        }
    };
    (@idx $n:expr; $head:ident $($tail:ident)*) => {
        #[allow(dead_code)]
        pub const $head: usize = $n;
        ck_struct!(@idx $n + 1usize; $($tail)*);
    };
    (@idx $n:expr;) => {
        /// Number of declared fields.
        #[allow(dead_code)]
        pub const FIELD_COUNT: usize = $n;
    };
}

ck_struct!(
    /// `CK_MECHANISM` (v3.2 §5.1.2) — the outer struct every `C_*Init` takes.
    /// Not itself a *parameter* struct, but read with the same arithmetic and
    /// therefore the same hazard: `pParameter` sits at offset 4 on wasm32 and
    /// offset 8 natively.
    mechanism, "CK_MECHANISM", {
    MECHANISM: F::Ulong,
    P_PARAMETER: F::Ptr,
    UL_PARAMETER_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_AES_CTR_PARAMS` (v3.2 §6.11.2) — **instance 1**. `cb` is at
    /// offset 4 on wasm32 and offset 8 on LP64.
    aes_ctr, "CK_AES_CTR_PARAMS", {
    UL_COUNTER_BITS: F::Ulong,
    CB: F::Bytes(16),
});

ck_struct!(
    /// `CK_EDDSA_PARAMS` (v3.2 §6.3.7) — **instance 2**. `phFlag` is a
    /// one-byte `CK_BBOOL`; the three (wasm32) or seven (LP64) bytes after it
    /// are padding and belong to nobody.
    eddsa, "CK_EDDSA_PARAMS", {
    PH_FLAG: F::Bbool,
    UL_CONTEXT_DATA_LEN: F::Ulong,
    P_CONTEXT_DATA: F::Ptr,
});

ck_struct!(
    /// Vendor KMAC parameters (`CKM_KMAC_128` / `CKM_KMAC_256`) —
    /// **instance 3**. The leading field is a **pointer**: reading it as a
    /// `u32` on LP64 kept its low half and then dereferenced it.
    kmac, "CK_PQCTODAY_KMAC_PARAMS", {
    P_CUSTOMIZATION: F::Ptr,
    UL_CUSTOMIZATION_LEN: F::Ulong,
    UL_OUTPUT_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_MAC_GENERAL_PARAMS` (v3.2 §6.x) — **instance 4**. A bare
    /// `typedef CK_ULONG`, so the "struct" is one native-width word.
    mac_general, "CK_MAC_GENERAL_PARAMS", {
    UL_MAC_LENGTH: F::Ulong,
});

ck_struct!(
    /// `CK_GCM_PARAMS` (v3.2 §6.27.7).
    gcm, "CK_GCM_PARAMS", {
    P_IV: F::Ptr,
    UL_IV_LEN: F::Ulong,
    UL_IV_BITS: F::Ulong,
    P_AAD: F::Ptr,
    UL_AAD_LEN: F::Ulong,
    UL_TAG_BITS: F::Ulong,
});

ck_struct!(
    /// `CK_CCM_PARAMS` (v3.2 §6.11.3).
    ccm, "CK_CCM_PARAMS", {
    UL_DATA_LEN: F::Ulong,
    P_NONCE: F::Ptr,
    UL_NONCE_LEN: F::Ulong,
    P_AAD: F::Ptr,
    UL_AAD_LEN: F::Ulong,
    UL_MAC_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_CHACHA20_PARAMS` (v3.2 §6.20).
    chacha20, "CK_CHACHA20_PARAMS", {
    P_BLOCK_COUNTER: F::Ptr,
    BLOCK_COUNTER_BITS: F::Ulong,
    P_NONCE: F::Ptr,
    UL_NONCE_BITS: F::Ulong,
});

ck_struct!(
    /// `CK_SALSA20_CHACHA20_POLY1305_PARAMS` (v3.2 §6.21).
    salsa20_poly1305, "CK_SALSA20_CHACHA20_POLY1305_PARAMS", {
    P_NONCE: F::Ptr,
    UL_NONCE_LEN: F::Ulong,
    P_AAD: F::Ptr,
    UL_AAD_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_RSA_PKCS_OAEP_PARAMS` (v3.2 §6.4.4).
    oaep, "CK_RSA_PKCS_OAEP_PARAMS", {
    HASH_ALG: F::Ulong,
    MGF: F::Ulong,
    SOURCE: F::Ulong,
    P_SOURCE_DATA: F::Ptr,
    UL_SOURCE_DATA_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_RSA_PKCS_PSS_PARAMS` (v3.2 §6.4.5).
    pss, "CK_RSA_PKCS_PSS_PARAMS", {
    HASH_ALG: F::Ulong,
    MGF: F::Ulong,
    S_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_ECDH1_DERIVE_PARAMS` (v3.2 §6.3.17).
    ecdh1, "CK_ECDH1_DERIVE_PARAMS", {
    KDF: F::Ulong,
    UL_SHARED_DATA_LEN: F::Ulong,
    P_SHARED_DATA: F::Ptr,
    UL_PUBLIC_DATA_LEN: F::Ulong,
    P_PUBLIC_DATA: F::Ptr,
});

ck_struct!(
    /// `CK_HKDF_PARAMS` (v3.2 §6.45). **The struct that rules out a bare
    /// field-index reader**: `bExtract` and `bExpand` are adjacent
    /// `CK_BBOOL`s at bytes 0 and 1, so field 1 is *not* at one word.
    hkdf, "CK_HKDF_PARAMS", {
    B_EXTRACT: F::Bbool,
    B_EXPAND: F::Bbool,
    PRF_HASH_MECHANISM: F::Ulong,
    UL_SALT_TYPE: F::Ulong,
    P_SALT: F::Ptr,
    UL_SALT_LEN: F::Ulong,
    H_SALT_KEY: F::Ulong,
    P_INFO: F::Ptr,
    UL_INFO_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_PKCS5_PBKD2_PARAMS2` (v3.2 §6.38).
    pbkd2, "CK_PKCS5_PBKD2_PARAMS2", {
    SALT_SOURCE: F::Ulong,
    P_SALT_SOURCE_DATA: F::Ptr,
    UL_SALT_SOURCE_DATA_LEN: F::Ulong,
    ITERATIONS: F::Ulong,
    PRF: F::Ulong,
    P_PRF_DATA: F::Ptr,
    UL_PRF_DATA_LEN: F::Ulong,
    P_PASSWORD: F::Ptr,
    UL_PASSWORD_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_SIGN_ADDITIONAL_CONTEXT` (v3.2 §6.67/§6.69).
    sign_ctx, "CK_SIGN_ADDITIONAL_CONTEXT", {
    HEDGE_VARIANT: F::Ulong,
    P_CONTEXT: F::Ptr,
    UL_CONTEXT_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_HASH_SIGN_ADDITIONAL_CONTEXT` (v3.2 §6.67.7/§6.69.7) — the
    /// previous struct plus a trailing `hash`.
    hash_sign_ctx, "CK_HASH_SIGN_ADDITIONAL_CONTEXT", {
    HEDGE_VARIANT: F::Ulong,
    P_CONTEXT: F::Ptr,
    UL_CONTEXT_LEN: F::Ulong,
    HASH: F::Ulong,
});

ck_struct!(
    /// `CK_KEY_DERIVATION_STRING_DATA` (v3.2 §6.43.4).
    key_deriv_string, "CK_KEY_DERIVATION_STRING_DATA", {
    P_DATA: F::Ptr,
    UL_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_PRF_DATA_PARAM` (v3.2 §6.42) — one element of the SP 800-108
    /// data-parameter array.
    prf_data_param, "CK_PRF_DATA_PARAM", {
    TYPE: F::Ulong,
    P_VALUE: F::Ptr,
    UL_VALUE_LEN: F::Ulong,
});

ck_struct!(
    /// `CK_SP800_108_COUNTER_FORMAT` (v3.2 §6.42).
    counter_format, "CK_SP800_108_COUNTER_FORMAT", {
    B_LITTLE_ENDIAN: F::Bbool,
    UL_WIDTH_IN_BITS: F::Ulong,
});

ck_struct!(
    /// `CK_SP800_108_DKM_LENGTH_FORMAT` (v3.2 §6.42) — `CK_BBOOL` in the
    /// middle, so field 2 sits at *two* words, not one plus a byte.
    dkm_length_format, "CK_SP800_108_DKM_LENGTH_FORMAT", {
    DKM_LENGTH_METHOD: F::Ulong,
    B_LITTLE_ENDIAN: F::Bbool,
    UL_WIDTH_IN_BITS: F::Ulong,
});

ck_struct!(
    /// `CK_SP800_108_KDF_PARAMS` (v3.2 §6.42). The trailing
    /// additional-derived-key pair is declared for completeness; this engine
    /// reads the first three fields only.
    sp800_108_kdf, "CK_SP800_108_KDF_PARAMS", {
    PRF_TYPE: F::Ulong,
    UL_NUMBER_OF_DATA_PARAMS: F::Ulong,
    P_DATA_PARAMS: F::Ptr,
    UL_ADDITIONAL_DERIVED_KEYS: F::Ulong,
    P_ADDITIONAL_DERIVED_KEYS: F::Ptr,
});

ck_struct!(
    /// `CK_SP800_108_FEEDBACK_KDF_PARAMS` (v3.2 §6.42).
    sp800_108_feedback, "CK_SP800_108_FEEDBACK_KDF_PARAMS", {
    PRF_TYPE: F::Ulong,
    UL_NUMBER_OF_DATA_PARAMS: F::Ulong,
    P_DATA_PARAMS: F::Ptr,
    UL_IV_LEN: F::Ulong,
    P_IV: F::Ptr,
    UL_ADDITIONAL_DERIVED_KEYS: F::Ulong,
    P_ADDITIONAL_DERIVED_KEYS: F::Ptr,
});

ck_struct!(
    /// `CK_HSS_KEY_PAIR_GEN_PARAMS` (v3.2 §6.14) — `CK_HSS_LEVELS ulLevels`
    /// followed by two eight-element `CK_LMS_TYPE`/`CK_LMOTS_TYPE` arrays.
    /// Declared element by element rather than as one `Bytes(...)` blob so
    /// that `LMS_0 + i` is a real field index and the per-element offsets
    /// come from the ABI like every other field here.
    hss_key_pair_gen, "CK_HSS_KEY_PAIR_GEN_PARAMS", {
    UL_LEVELS: F::Ulong,
    LMS_0: F::Ulong, LMS_1: F::Ulong, LMS_2: F::Ulong, LMS_3: F::Ulong,
    LMS_4: F::Ulong, LMS_5: F::Ulong, LMS_6: F::Ulong, LMS_7: F::Ulong,
    LMOTS_0: F::Ulong, LMOTS_1: F::Ulong, LMOTS_2: F::Ulong, LMOTS_3: F::Ulong,
    LMOTS_4: F::Ulong, LMOTS_5: F::Ulong, LMOTS_6: F::Ulong, LMOTS_7: F::Ulong,
});

ck_struct!(
    /// A bare `CK_OBJECT_HANDLE` mechanism parameter
    /// (`CKM_CONCATENATE_BASE_AND_KEY`, v3.2 §6.43.3).
    object_handle_param, "CK_OBJECT_HANDLE", {
    H_KEY: F::Ulong,
});

ck_struct!(
    /// `CK_BIP32_CHILD_DERIVE_PARAMS` — a **PQCToday vendor extension**, not
    /// an OASIS structure. `CKM_BIP32_CHILD_DERIVE` is
    /// `CKM_VENDOR_DEFINED | 0x105c`; neither the mechanism nor the struct
    /// appears in `docs/refs/pkcs11t-canonical-v3.2.h` or in the v3.2
    /// Standard's text. `src/lib/pkcs11/pkcs11t.h:2139` is therefore the sole
    /// definition, and it is what a third party compiles against:
    ///
    /// ```c
    /// typedef struct CK_BIP32_CHILD_DERIVE_PARAMS {
    ///     CK_VOID_PTR pNext;
    ///     CK_BIP32_CHILD_DERIVE_PARAMS_FLAGS flags;   /* CK_ULONG */
    ///     CK_BIP32_CHILD_DERIVE_PARAMS_INDEX index;   /* CK_ULONG */
    /// } CK_BIP32_CHILD_DERIVE_PARAMS;
    /// ```
    ///
    /// So `flags` is at one word and `index` at two — 24 bytes on LP64, 12 on
    /// wasm32. The C++ engine already reads it exactly this way and rejects
    /// any other `ulParameterLen` (`SoftHSM_keygen.cpp:3010`). Until
    /// 2026-08-14 the Rust engine read two **`u32`s at offsets 0 and 4**, so
    /// it took `pNext` as `flags` and, on LP64, the high half of `pNext` as
    /// `index` — a field-ORDER defect on top of a width one, on every target.
    bip32_child_derive, "CK_BIP32_CHILD_DERIVE_PARAMS", {
    P_NEXT: F::Ptr,
    FLAGS: F::Ulong,
    INDEX: F::Ulong,
});

/// Read a `CK_MECHANISM`. The mechanism type is narrowed to the engine's
/// internal `u32`; `ck_abi`'s adapters already reject an out-of-range
/// mechanism before this point on the native surface.
///
/// # Safety
/// `p_mechanism` must point to a readable `CK_MECHANISM`.
#[derive(Clone, Copy, Debug)]
pub struct Mech {
    pub mechanism: u32,
    pub p_parameter: *const u8,
    pub ul_parameter_len: usize,
}

/// A NULL `p_mechanism` yields `mechanism: 0`, which matches nothing in any
/// dispatch table, so the call site's own `CKR_MECHANISM_INVALID` /
/// `CKR_ARGUMENTS_BAD` path handles it. That is deliberate: the alternative
/// at the five entry points that do not null-check first is dereferencing
/// NULL, which is what the hand-rolled `*(p_mechanism as *const u32)` did.
///
/// # Safety
/// `p_mechanism` must be NULL or point to a readable `CK_MECHANISM`.
pub unsafe fn mech(p_mechanism: *const u8) -> Mech {
    // A non-NULL CK_MECHANISM is always fully present — it is a direct
    // argument, not a caller-declared-length blob — so this is the one place
    // the length is the struct's own size rather than something the caller
    // told us.
    let r = match unsafe {
        ParamReader::new(
            p_mechanism,
            mechanism::LAYOUT.size(),
            &mechanism::LAYOUT,
            mechanism::FIELD_COUNT,
        )
    } {
        Ok(r) => r,
        Err(_) => {
            return Mech { mechanism: 0, p_parameter: core::ptr::null(), ul_parameter_len: 0 };
        }
    };
    Mech {
        mechanism: unsafe { r.ulong32(mechanism::MECHANISM) },
        p_parameter: unsafe { r.ptr(mechanism::P_PARAMETER) },
        ul_parameter_len: unsafe { r.ulong(mechanism::UL_PARAMETER_LEN) },
    }
}

impl Mech {
    /// Build a reader over this mechanism's parameter.
    ///
    /// # Safety
    /// `p_parameter`/`ul_parameter_len` must describe readable memory.
    pub unsafe fn params<'a>(
        &self,
        layout: &'static Struct,
        min_fields: usize,
    ) -> Result<ParamReader<'a>, ParamErr> {
        unsafe { ParamReader::new(self.p_parameter, self.ul_parameter_len, layout, min_fields) }
    }

    /// Build a reader over an *optional* parameter — `Ok(None)` when absent.
    ///
    /// # Safety
    /// As [`params`](Self::params).
    pub unsafe fn opt_params<'a>(
        &self,
        layout: &'static Struct,
        min_fields: usize,
    ) -> Result<Option<ParamReader<'a>>, ParamErr> {
        unsafe { ParamReader::optional(self.p_parameter, self.ul_parameter_len, layout, min_fields) }
    }

    /// True when the caller supplied a non-empty mechanism parameter.
    pub fn has_param(&self) -> bool {
        !self.p_parameter.is_null() && self.ul_parameter_len > 0
    }

    /// The parameter as a raw byte slice (for the mechanisms whose parameter
    /// is a bare byte string — an AES-CBC IV, say — rather than a struct).
    ///
    /// # Safety
    /// `p_parameter`/`ul_parameter_len` must describe readable memory.
    pub unsafe fn raw<'a>(&self) -> &'a [u8] {
        if !self.has_param() {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.p_parameter, self.ul_parameter_len) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Layout arithmetic, pinned for BOTH ABIs ─────────────────────────
    //
    // Ground truth: the vendored `src/lib/pkcs11/pkcs11t.h` put through a C
    // compiler. LP64 numbers come from running `offsetof`/`sizeof` on this
    // host; ILP32 numbers from `_Static_assert`s compiled for
    // i386-apple-macosx, i686-unknown-linux-gnu and armv7-unknown-linux-
    // gnueabihf (all three agree). The point of testing both here is that
    // `cargo test` only ever runs the LP64 build — without a width-parametric
    // `offset_at`, the wasm32 half of every layout would be unverified.

    /// (layout, ILP32 offsets, ILP32 sizeof, LP64 offsets, LP64 sizeof)
    fn table() -> Vec<(&'static Struct, Vec<usize>, usize, Vec<usize>, usize)> {
        vec![
            (&mechanism::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&aes_ctr::LAYOUT, vec![0, 4], 20, vec![0, 8], 24),
            (&eddsa::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&kmac::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&mac_general::LAYOUT, vec![0], 4, vec![0], 8),
            (&gcm::LAYOUT, vec![0, 4, 8, 12, 16, 20], 24, vec![0, 8, 16, 24, 32, 40], 48),
            (&chacha20::LAYOUT, vec![0, 4, 8, 12], 16, vec![0, 8, 16, 24], 32),
            (&salsa20_poly1305::LAYOUT, vec![0, 4, 8, 12], 16, vec![0, 8, 16, 24], 32),
            (&oaep::LAYOUT, vec![0, 4, 8, 12, 16], 20, vec![0, 8, 16, 24, 32], 40),
            (&pss::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&ecdh1::LAYOUT, vec![0, 4, 8, 12, 16], 20, vec![0, 8, 16, 24, 32], 40),
            (
                &hkdf::LAYOUT,
                vec![0, 1, 4, 8, 12, 16, 20, 24, 28],
                32,
                vec![0, 1, 8, 16, 24, 32, 40, 48, 56],
                64,
            ),
            (
                &pbkd2::LAYOUT,
                vec![0, 4, 8, 12, 16, 20, 24, 28, 32],
                36,
                vec![0, 8, 16, 24, 32, 40, 48, 56, 64],
                72,
            ),
            (&sign_ctx::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&hash_sign_ctx::LAYOUT, vec![0, 4, 8, 12], 16, vec![0, 8, 16, 24], 32),
            (&key_deriv_string::LAYOUT, vec![0, 4], 8, vec![0, 8], 16),
            (&prf_data_param::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&counter_format::LAYOUT, vec![0, 4], 8, vec![0, 8], 16),
            (&dkm_length_format::LAYOUT, vec![0, 4, 8], 12, vec![0, 8, 16], 24),
            (&sp800_108_kdf::LAYOUT, vec![0, 4, 8, 12, 16], 20, vec![0, 8, 16, 24, 32], 40),
            (
                &sp800_108_feedback::LAYOUT,
                vec![0, 4, 8, 12, 16, 20, 24],
                28,
                vec![0, 8, 16, 24, 32, 40, 48],
                56,
            ),
            (&object_handle_param::LAYOUT, vec![0], 4, vec![0], 8),
            (
                &hss_key_pair_gen::LAYOUT,
                (0..17).map(|i| i * 4).collect(),
                68,
                (0..17).map(|i| i * 8).collect(),
                136,
            ),
        ]
    }

    #[test]
    fn layout_offsets_match_the_c_abi_on_ilp32_and_lp64() {
        for (l, off32, size32, off64, size64) in table() {
            assert_eq!(l.fields.len(), off32.len(), "{}: ILP32 row width", l.name);
            assert_eq!(l.fields.len(), off64.len(), "{}: LP64 row width", l.name);
            for i in 0..l.fields.len() {
                assert_eq!(
                    offset_at(l.fields, i, 4),
                    off32[i],
                    "{}[{}] on ILP32 (wasm32/emscripten)",
                    l.name,
                    i
                );
                assert_eq!(offset_at(l.fields, i, 8), off64[i], "{}[{}] on LP64", l.name, i);
            }
            assert_eq!(size_at(l.fields, 4), size32, "sizeof({}) on ILP32", l.name);
            assert_eq!(size_at(l.fields, 8), size64, "sizeof({}) on LP64", l.name);
        }
    }

    #[test]
    fn this_targets_offsets_are_the_ones_the_table_pins() {
        let word = WORD;
        for (l, off32, size32, off64, size64) in table() {
            let (want_off, want_size) =
                if word == 4 { (off32, size32) } else { (off64, size64) };
            for i in 0..l.fields.len() {
                assert_eq!(l.offset(i), want_off[i], "{}[{}] on this target", l.name, i);
            }
            assert_eq!(l.size(), want_size, "sizeof({}) on this target", l.name);
        }
    }

    #[test]
    fn min_len_is_the_require_len_guard() {
        // Nothing required ⇒ nothing demanded of the caller.
        assert_eq!(gcm::LAYOUT.min_len(0), 0);
        // Only pIv+ulIvLen wanted ⇒ two words, not the whole 48-byte struct.
        assert_eq!(gcm::LAYOUT.min_len(2), 2 * WORD);
        assert_eq!(gcm::LAYOUT.min_len(gcm::FIELD_COUNT), gcm::LAYOUT.size());
        // AES-CTR's tail is a byte array, so the full struct is word+16 with
        // no trailing padding on either ABI.
        assert_eq!(aes_ctr::LAYOUT.min_len(2), WORD + 16);
        // A CK_BBOOL-only prefix is ONE byte.
        assert_eq!(eddsa::LAYOUT.min_len(1), 1);
        assert_eq!(hkdf::LAYOUT.min_len(2), 2);
    }

    // ── The reader itself ───────────────────────────────────────────────

    /// Serialise a parameter struct at this target's native widths.
    /// `Vals` mirrors `F`.
    enum V {
        U(usize),
        P(*const u8),
        B(u8),
        Raw(Vec<u8>),
    }

    fn build(l: &'static Struct, vals: &[V]) -> Vec<u8> {
        let mut buf = vec![0u8; l.size()];
        for (i, v) in vals.iter().enumerate() {
            let off = l.offset(i);
            match v {
                V::U(x) => buf[off..off + WORD].copy_from_slice(&x.to_ne_bytes()),
                V::P(p) => buf[off..off + WORD].copy_from_slice(&(*p as usize).to_ne_bytes()),
                V::B(b) => buf[off] = *b,
                V::Raw(r) => buf[off..off + r.len()].copy_from_slice(r),
            }
        }
        buf
    }

    #[test]
    fn short_buffer_fails_cleanly_instead_of_over_reading() {
        let buf = vec![0u8; gcm::LAYOUT.size() - 1];
        let e = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &gcm::LAYOUT, gcm::FIELD_COUNT)
        }
        .unwrap_err();
        assert_eq!(e, ParamErr::TooShort);
        // …and a prefix the caller DID supply is still readable.
        let r = unsafe { ParamReader::new(buf.as_ptr(), buf.len(), &gcm::LAYOUT, 2) }.unwrap();
        assert!(r.covers(2));
        assert!(!r.covers(gcm::FIELD_COUNT));
        assert_eq!(r.require_len(gcm::FIELD_COUNT), Err(ParamErr::TooShort));
    }

    #[test]
    fn absent_and_short_are_distinguished() {
        assert_eq!(
            unsafe { ParamReader::new(core::ptr::null(), 0, &gcm::LAYOUT, 1) }.unwrap_err(),
            ParamErr::Absent
        );
        let buf = [0u8; 1];
        assert_eq!(
            unsafe { ParamReader::new(buf.as_ptr(), 1, &gcm::LAYOUT, 1) }.unwrap_err(),
            ParamErr::TooShort
        );
        assert!(
            unsafe { ParamReader::optional(core::ptr::null(), 0, &gcm::LAYOUT, 1) }
                .unwrap()
                .is_none()
        );
        // A present-but-short parameter is NOT silently treated as absent.
        assert_eq!(
            unsafe { ParamReader::optional(buf.as_ptr(), 1, &gcm::LAYOUT, 1) }.unwrap_err(),
            ParamErr::TooShort
        );
    }

    #[test]
    fn round_trips_every_accessor() {
        let label = b"a-label".to_vec();
        let buf = build(
            &oaep::LAYOUT,
            &[
                V::U(0x250),
                V::U(0x0002),
                V::U(1),
                V::P(label.as_ptr()),
                V::U(label.len()),
            ],
        );
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &oaep::LAYOUT, oaep::FIELD_COUNT)
        }
        .unwrap();
        assert_eq!(unsafe { r.ulong32(oaep::HASH_ALG) }, 0x250);
        assert_eq!(unsafe { r.ulong(oaep::UL_SOURCE_DATA_LEN) }, label.len());
        assert_eq!(unsafe { r.buffer(oaep::P_SOURCE_DATA, oaep::UL_SOURCE_DATA_LEN) }, &label[..]);

        let cb: Vec<u8> = (0xa0u8..0xb0).collect();
        let buf = build(&aes_ctr::LAYOUT, &[V::U(128), V::Raw(cb.clone())]);
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &aes_ctr::LAYOUT, aes_ctr::FIELD_COUNT)
        }
        .unwrap();
        assert_eq!(unsafe { r.ulong(aes_ctr::UL_COUNTER_BITS) }, 128);
        assert_eq!(unsafe { r.bytes(aes_ctr::CB) }, &cb[..]);
    }

    #[test]
    fn null_pointer_or_zero_length_yields_an_empty_buffer() {
        let buf = build(
            &eddsa::LAYOUT,
            &[V::B(0), V::U(0), V::P(core::ptr::null())],
        );
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &eddsa::LAYOUT, eddsa::FIELD_COUNT)
        }
        .unwrap();
        assert!(unsafe { r.buffer(eddsa::P_CONTEXT_DATA, eddsa::UL_CONTEXT_DATA_LEN) }.is_empty());
    }

    #[test]
    #[should_panic(expected = "read as")]
    fn reading_a_bbool_as_a_ulong_is_caught() {
        let buf = build(&eddsa::LAYOUT, &[V::B(1), V::U(0), V::P(core::ptr::null())]);
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &eddsa::LAYOUT, eddsa::FIELD_COUNT)
        }
        .unwrap();
        let _ = unsafe { r.ulong(eddsa::PH_FLAG) };
    }

    // ── The four known-bad readings, reconstructed ──────────────────────
    //
    // Each `old_*` below is the pre-fix reading, transcribed from the commit
    // that removed it. A test that only showed the new reader agreeing with
    // itself would prove nothing; these show the two disagreeing, on inputs a
    // conformant caller can produce.

    /// Instance 1 — `844ed27`: "ulCounterBits(CK_ULONG=4) + cb[16] = 20 bytes",
    /// `cb` taken from offset 4.
    unsafe fn old_aes_ctr_cb(p: *const u8) -> Vec<u8> {
        unsafe { core::slice::from_raw_parts(p.add(4), 16) }.to_vec()
    }

    #[test]
    fn instance_1_aes_ctr_counter_block_was_four_bytes_early() {
        let cb: Vec<u8> = vec![
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf,
        ];
        let buf = build(&aes_ctr::LAYOUT, &[V::U(128), V::Raw(cb.clone())]);
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &aes_ctr::LAYOUT, aes_ctr::FIELD_COUNT)
        }
        .unwrap();
        let new = unsafe { r.bytes(aes_ctr::CB) };
        assert_eq!(new, &cb[..], "the reader returns the caller's counter block");

        if WORD == 8 {
            let old = unsafe { old_aes_ctr_cb(buf.as_ptr()) };
            assert_ne!(old, cb, "the old 4-byte-offset reading must disagree");
            // Exactly the corruption 844ed27 measured against OpenSSL:
            // a0a1…aeaf became 00000000a0a1…aaab.
            assert_eq!(
                old,
                vec![
                    0x00, 0x00, 0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                    0xa9, 0xaa, 0xab
                ]
            );
        }
    }

    /// Instance 2 — `7f66aae`: `phFlag` read as a `u32` at offset 0.
    unsafe fn old_eddsa_ph_flag(p: *const u8) -> bool {
        unsafe { core::ptr::read_unaligned(p as *const u32) != 0 }
    }

    #[test]
    fn instance_2_eddsa_ph_flag_took_three_bytes_of_padding_with_it() {
        // A caller that writes phFlag = CK_FALSE into a struct it did not
        // zero first. The padding bytes belong to nobody; the spec says
        // nothing about them because nothing may read them.
        let mut buf = build(&eddsa::LAYOUT, &[V::B(0), V::U(0), V::P(core::ptr::null())]);
        buf[1] = 0xde;
        buf[2] = 0xad;
        buf[3] = 0xbe;

        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &eddsa::LAYOUT, eddsa::FIELD_COUNT)
        }
        .unwrap();
        assert!(
            !unsafe { r.bbool(eddsa::PH_FLAG) },
            "CK_FALSE with dirty padding must stay pure EdDSA"
        );
        assert!(
            unsafe { old_eddsa_ph_flag(buf.as_ptr()) },
            "the old u32 reading selected the PRE-HASH variant — a silently \
             wrong signature from a valid call, on EVERY target"
        );

        // …and the true case is still true, from byte 0 alone.
        let buf = build(&eddsa::LAYOUT, &[V::B(1), V::U(0), V::P(core::ptr::null())]);
        let r = unsafe {
            ParamReader::new(buf.as_ptr(), buf.len(), &eddsa::LAYOUT, eddsa::FIELD_COUNT)
        }
        .unwrap();
        assert!(unsafe { r.bbool(eddsa::PH_FLAG) });
    }

    /// Instance 3 — `7f66aae`: pCustomization / ulCustomizationLen /
    /// ulOutputLen read as three `u32`s.
    unsafe fn old_kmac(p: *const u8) -> (usize, usize, u32) {
        let w = p as *const u32;
        unsafe {
            (
                core::ptr::read_unaligned(w) as usize,
                core::ptr::read_unaligned(w.add(1)) as usize,
                core::ptr::read_unaligned(w.add(2)),
            )
        }
    }

    #[test]
    fn instance_3_kmac_truncated_a_pointer_and_then_dereferenced_it() {
        let custom = b"KMAC customization".to_vec();
        let buf = build(
            &kmac::LAYOUT,
            &[V::P(custom.as_ptr()), V::U(custom.len()), V::U(32)],
        );
        let r =
            unsafe { ParamReader::new(buf.as_ptr(), buf.len(), &kmac::LAYOUT, kmac::FIELD_COUNT) }
                .unwrap();
        assert_eq!(unsafe { r.ptr(kmac::P_CUSTOMIZATION) }, custom.as_ptr());
        assert_eq!(unsafe { r.ulong(kmac::UL_CUSTOMIZATION_LEN) }, custom.len());
        assert_eq!(unsafe { r.ulong32(kmac::UL_OUTPUT_LEN) }, 32);
        assert_eq!(
            unsafe { r.buffer(kmac::P_CUSTOMIZATION, kmac::UL_CUSTOMIZATION_LEN) },
            &custom[..]
        );

        if WORD == 8 {
            let (old_ptr, old_len, old_out) = unsafe { old_kmac(buf.as_ptr()) };
            // The pointer kept only its low half…
            assert_eq!(old_ptr, custom.as_ptr() as usize & 0xFFFF_FFFF);
            assert_ne!(
                old_ptr,
                custom.as_ptr() as usize,
                "the old reading truncated the customization pointer — and \
                 the engine then dereferenced it"
            );
            // …ulCustomizationLen came from the pointer's HIGH half…
            assert_eq!(old_len, custom.as_ptr() as usize >> 32);
            assert_ne!(old_len, custom.len());
            // …and ulOutputLen came from the low half of ulCustomizationLen.
            assert_eq!(old_out as usize, custom.len());
            assert_ne!(old_out, 32);
        }
    }

    /// Instance 4 — `7f66aae`: a bare `CK_ULONG` read as a `u32`, with a
    /// 4-byte length guard.
    unsafe fn old_mac_general(p: *const u8) -> u32 {
        unsafe { core::ptr::read_unaligned(p as *const u32) }
    }

    #[test]
    fn instance_4_mac_general_read_half_a_ck_ulong() {
        let buf = build(&mac_general::LAYOUT, &[V::U(16)]);
        let r = unsafe {
            ParamReader::new(
                buf.as_ptr(),
                buf.len(),
                &mac_general::LAYOUT,
                mac_general::FIELD_COUNT,
            )
        }
        .unwrap();
        assert_eq!(unsafe { r.ulong(mac_general::UL_MAC_LENGTH) }, 16);

        // Little-endian-safe, which is why it was latent — but the LENGTH
        // GUARD was not. The old code accepted `ulParameterLen == 4`, i.e.
        // half a CK_ULONG, and read the other half from beyond the buffer.
        let half = vec![16u8, 0, 0, 0];
        assert_eq!(unsafe { old_mac_general(half.as_ptr()) }, 16, "old guard accepted 4 bytes");
        if WORD == 8 {
            assert_eq!(
                unsafe {
                    ParamReader::new(
                        half.as_ptr(),
                        half.len(),
                        &mac_general::LAYOUT,
                        mac_general::FIELD_COUNT,
                    )
                }
                .unwrap_err(),
                ParamErr::TooShort,
                "the reader refuses the half-sized parameter instead of \
                 reading four bytes past it"
            );
        }

        // And on a big-endian LP64 host the old reading yields 0, not 16 —
        // shown here by construction rather than by cross-compiling.
        let be = 16usize.to_be_bytes();
        if WORD == 8 {
            assert_eq!(unsafe { old_mac_general(be.as_ptr()) }, 0);
        }
    }

    /// The `CK_HKDF_PARAMS` case that rules out a bare field-index reader.
    #[test]
    fn packed_bbools_are_not_at_word_multiples() {
        let mut buf = build(
            &hkdf::LAYOUT,
            &[
                V::B(1),
                V::B(0),
                V::U(0x250),
                V::U(2),
                V::P(core::ptr::null()),
                V::U(0),
                V::U(0),
                V::P(core::ptr::null()),
                V::U(0),
            ],
        );
        buf[1] = 1; // bExpand = CK_TRUE, at byte 1 — NOT at one word.
        let r =
            unsafe { ParamReader::new(buf.as_ptr(), buf.len(), &hkdf::LAYOUT, hkdf::FIELD_COUNT) }
                .unwrap();
        assert!(unsafe { r.bbool(hkdf::B_EXTRACT) });
        assert!(unsafe { r.bbool(hkdf::B_EXPAND) });
        assert_eq!(unsafe { r.ulong32(hkdf::PRF_HASH_MECHANISM) }, 0x250);
        // What a `i * size_of::<usize>()` reader would have called bExpand:
        assert_eq!(hkdf::LAYOUT.offset(hkdf::B_EXPAND), 1);
        assert_ne!(hkdf::LAYOUT.offset(hkdf::B_EXPAND), WORD);
        assert_eq!(hkdf::LAYOUT.offset(hkdf::PRF_HASH_MECHANISM), WORD);
    }

    #[test]
    fn a_null_mechanism_is_mechanism_zero_not_a_dereference() {
        let m = unsafe { mech(core::ptr::null()) };
        assert_eq!(m.mechanism, 0);
        assert!(!m.has_param());
    }

    #[test]
    fn mech_reads_the_outer_struct_at_native_width() {
        let param = build(&mac_general::LAYOUT, &[V::U(20)]);
        let m = build(
            &mechanism::LAYOUT,
            &[V::U(0x0000_0251), V::P(param.as_ptr()), V::U(param.len())],
        );
        let got = unsafe { mech(m.as_ptr()) };
        assert_eq!(got.mechanism, 0x0000_0251);
        assert_eq!(got.p_parameter, param.as_ptr());
        assert_eq!(got.ul_parameter_len, WORD);
        let r = unsafe { got.params(&mac_general::LAYOUT, 1) }.unwrap();
        assert_eq!(unsafe { r.ulong(mac_general::UL_MAC_LENGTH) }, 20);
    }
}
