//! P0-1 spike (implementation-plan-classic-mceliece-all-parameter-sets-2026-09-08.md):
//! prove that `classic-mceliece-rust`'s per-variant `cfg(feature = "...")` constants
//! (params.rs — GFBITS/SYS_N/SYS_T, primary; COND_BYTES/IRR_BYTES/PK_NROWS/PK_NCOLS/
//! PK_ROW_BYTES/SYND_BYTES/GFMASK, all `const fn`-derived from those three using only
//! `+ - * << .div_ceil()`) can drive per-variant buffer sizes in ONE compiled binary,
//! so all 10 parameter sets compile together instead of one Cargo feature per build.
//!
//! THROWAWAY — not shipped code. Proves the sizing/const-generics pattern only; does
//! not reimplement the actual Goppa-code/Benes-network algorithm bodies (Phase 1's
//! job, porting real upstream logic file-by-file onto this pattern). Delete this
//! crate once Phase 1's real fork (`rust/classic-mceliece-multi/`) lands.
//!
//! **First attempt failed, and that failure is itself the useful result.** The
//! obvious design — a `trait McElieceParams { const CRYPTO_PUBLICKEYBYTES: usize
//! = ...; }`, then `struct PublicKey<P: McElieceParams>([u8; P::CRYPTO_PUBLICKEYBYTES])`
//! — does not compile on stable Rust: `error: generic parameters may not be used in
//! const operations ... type parameters may not be used in const expressions`. An
//! associated const reached through a still-generic type parameter cannot size an
//! array; the compiler cannot prove it's fixed until monomorphization, and stable
//! Rust doesn't permit that proof outside the unstable `generic_const_exprs`
//! feature — exactly the limitation the plan's own §4.2 fallback note anticipated,
//! now CONFIRMED by the compiler rather than assumed from documentation.
//!
//! **What does work on stable**: a bare `const N: usize` generic parameter directly
//! on the struct/function (supported since Rust 1.51, "min_const_generics") — the
//! array length is the const generic parameter itself, not a further-generic type's
//! associated item. Each parameter set becomes a *value* substituted at a concrete
//! call site (a type alias, or an inline `{ ... }` const block using the trait's
//! associated const AS A CONCRETE EXPRESSION at that one non-generic site — legal,
//! because at the alias/call site `P` is a concrete type, not a generic parameter).
//! The `McElieceParams` trait still earns its keep: it's the single, checked source
//! of every derived size (so a hand-copied number can never silently drift from the
//! GFBITS/SYS_N/SYS_T it's derived from), it's just not usable as the generic *type*
//! parameter of the buffer types themselves.
#![forbid(unsafe_code)]

/// One parameter set's sizes — unchanged in spirit from the first draft. The 3
/// "primary" consts are copied verbatim from upstream's per-feature block in
/// `params.rs`; the 7 GFBITS/SYS_N/SYS_T-derived ones are upstream's own formulas
/// (real, not guessed — independently verified below to reproduce §1.1's public-key
/// and ciphertext sizes exactly). `CRYPTO_SECRETKEYBYTES` is NOT one of upstream's
/// derived formulas — api.rs states it as a bare per-variant literal with no
/// derivation in this crate at all, so it has no default here either; a first draft
/// of this spike guessed a formula for it (`SYS_N/8 + IRR_BYTES + COND_BYTES + 32`)
/// that was off by 8 bytes against the real 6492 for 348864 — caught by the test
/// below before being trusted, and removed rather than "fixed" with another guess.
pub trait McElieceParams {
    const NAME: &'static str;
    const GFBITS: usize;
    const SYS_N: usize;
    const SYS_T: usize;
    const SEMI_SYSTEMATIC: bool; // the 'f' variants' key-generation-only switch

    const COND_BYTES: usize = (1 << (Self::GFBITS - 4)) * (2 * Self::GFBITS - 1);
    const IRR_BYTES: usize = Self::SYS_T * 2;
    const PK_NROWS: usize = Self::SYS_T * Self::GFBITS;
    const PK_NCOLS: usize = Self::SYS_N - Self::PK_NROWS;
    const PK_ROW_BYTES: usize = Self::PK_NCOLS.div_ceil(8);
    const SYND_BYTES: usize = Self::PK_NROWS.div_ceil(8);
    const GFMASK: usize = (1 << Self::GFBITS) - 1;

    const CRYPTO_PUBLICKEYBYTES: usize = Self::PK_NROWS * Self::PK_ROW_BYTES;
    const CRYPTO_SECRETKEYBYTES: usize;
    const CRYPTO_CIPHERTEXTBYTES: usize = Self::SYND_BYTES;
    const CRYPTO_BYTES: usize = 32;
}

/// mceliece348864 — the smallest variant (NIST category 1). Non-`f` (fully
/// systematic keygen); `SEMI_SYSTEMATIC` only ever affects `sk_gen`'s internal
/// control-bit generation path (not modeled in this spike — see the module doc).
pub struct Mceliece348864;
impl McElieceParams for Mceliece348864 {
    const NAME: &'static str = "mceliece348864";
    const GFBITS: usize = 12;
    const SYS_N: usize = 3488;
    const SYS_T: usize = 64;
    const SEMI_SYSTEMATIC: bool = false;
    const CRYPTO_SECRETKEYBYTES: usize = 6_492; // upstream api.rs literal
}

/// mceliece8192128f — the largest variant (NIST category 5, semi-systematic).
/// Deliberately the size extreme opposite `Mceliece348864`, matching the same
/// pair the liboqs build spike (P0-2) round-tripped.
pub struct Mceliece8192128f;
impl McElieceParams for Mceliece8192128f {
    const NAME: &'static str = "mceliece8192128f";
    const GFBITS: usize = 13;
    const SYS_N: usize = 8192;
    const SYS_T: usize = 128;
    const SEMI_SYSTEMATIC: bool = true;
    const CRYPTO_SECRETKEYBYTES: usize = 14_120; // upstream api.rs literal
}

/// Sized by a bare const-generic parameter (works on stable), not by a trait
/// associated const reached through a generic type (does not — see module doc).
/// The `P: McElieceParams` type parameter is kept as a `PhantomData` purely so a
/// caller still gets a type distinguishing "a 348864 key" from "an 8192128f key"
/// of the SAME byte length by coincidence (none happen to collide here, but two
/// different parameter sets sharing a buffer length is not something to rule out
/// in general) — it plays no role in sizing the array.
pub struct PublicKey<P: McElieceParams, const N: usize>(pub [u8; N], core::marker::PhantomData<P>);
pub struct SecretKey<P: McElieceParams, const N: usize>(pub [u8; N], core::marker::PhantomData<P>);
pub struct Ciphertext<P: McElieceParams, const N: usize>(pub [u8; N], core::marker::PhantomData<P>);
pub struct SharedSecret<P: McElieceParams, const N: usize>(pub [u8; N], core::marker::PhantomData<P>);

impl<P: McElieceParams, const N: usize> PublicKey<P, N> {
    pub fn zeroed() -> Self {
        Self([0u8; N], core::marker::PhantomData)
    }
}
impl<P: McElieceParams, const N: usize> SecretKey<P, N> {
    pub fn zeroed() -> Self {
        Self([0u8; N], core::marker::PhantomData)
    }
}
impl<P: McElieceParams, const N: usize> Ciphertext<P, N> {
    pub fn zeroed() -> Self {
        Self([0u8; N], core::marker::PhantomData)
    }
}
impl<P: McElieceParams, const N: usize> SharedSecret<P, N> {
    pub fn zeroed() -> Self {
        Self([0u8; N], core::marker::PhantomData)
    }
}

// Per-variant type aliases — this is the "concrete call site" where a trait
// associated const legally becomes a const-generic ARGUMENT (evaluated once,
// eagerly, because `Mceliece348864`/`Mceliece8192128f` are concrete types here,
// not generic parameters). This is exactly the shape Phase 1's real port would
// expose per variant, so a caller never writes the byte count out by hand.
pub type PublicKey348864 = PublicKey<Mceliece348864, { Mceliece348864::CRYPTO_PUBLICKEYBYTES }>;
pub type SecretKey348864 = SecretKey<Mceliece348864, { Mceliece348864::CRYPTO_SECRETKEYBYTES }>;
pub type Ciphertext348864 =
    Ciphertext<Mceliece348864, { Mceliece348864::CRYPTO_CIPHERTEXTBYTES }>;

pub type PublicKey8192128f =
    PublicKey<Mceliece8192128f, { Mceliece8192128f::CRYPTO_PUBLICKEYBYTES }>;
pub type SecretKey8192128f =
    SecretKey<Mceliece8192128f, { Mceliece8192128f::CRYPTO_SECRETKEYBYTES }>;
pub type Ciphertext8192128f =
    Ciphertext<Mceliece8192128f, { Mceliece8192128f::CRYPTO_CIPHERTEXTBYTES }>;

/// One function, generic over the buffer length directly (not over `P`), doing
/// something a real algorithm step would: build a syndrome-shaped buffer from a
/// public key. The actual encaps/decaps math is Phase 1's job — this exercises
/// the SAME "N determined by which variant you're in" plumbing real math would
/// run through, over BOTH const-generic parameters at once (`N` for the input
/// key, `M` for the differently-sized output) — the part this spike tests.
pub fn syndrome_shaped_buffer<P: McElieceParams, const N: usize, const M: usize>(
    _pk: &PublicKey<P, N>,
) -> [u8; M] {
    [0u8; M]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mceliece348864_matches_official_sizes() {
        assert_eq!(Mceliece348864::CRYPTO_PUBLICKEYBYTES, 261_120);
        assert_eq!(Mceliece348864::CRYPTO_SECRETKEYBYTES, 6_492);
        assert_eq!(Mceliece348864::CRYPTO_CIPHERTEXTBYTES, 96);
        assert_eq!(Mceliece348864::CRYPTO_BYTES, 32);
    }

    #[test]
    fn mceliece8192128f_matches_official_sizes() {
        assert_eq!(Mceliece8192128f::CRYPTO_PUBLICKEYBYTES, 1_357_824);
        assert_eq!(Mceliece8192128f::CRYPTO_SECRETKEYBYTES, 14_120);
        assert_eq!(Mceliece8192128f::CRYPTO_CIPHERTEXTBYTES, 208);
        assert_eq!(Mceliece8192128f::CRYPTO_BYTES, 32);
    }

    #[test]
    fn both_variants_coexist_in_one_binary() {
        // The actual P0-1 question: do two wildly different parameter sets'
        // instantiations both exist, both correctly sized, in the SAME compiled
        // crate — proving the one-set-per-build limitation is a Cargo-feature
        // artifact of the ORIGINAL crate's design, not a language-level ceiling
        // (it took a real design change -- const-generic N, not associated-const
        // P::N -- to get there; see the module doc for the failed first attempt).
        let pk_small = PublicKey348864::zeroed();
        let pk_large = PublicKey8192128f::zeroed();
        assert_eq!(pk_small.0.len(), 261_120);
        assert_eq!(pk_large.0.len(), 1_357_824);
        assert_ne!(pk_small.0.len(), pk_large.0.len());

        let synd_small: [u8; 96] = syndrome_shaped_buffer(&pk_small);
        let synd_large: [u8; 208] = syndrome_shaped_buffer(&pk_large);
        assert_eq!(synd_small.len(), 96);
        assert_eq!(synd_large.len(), 208);
    }

    #[test]
    fn sk_zeroed_both_sizes() {
        let sk_small = SecretKey348864::zeroed();
        let sk_large = SecretKey8192128f::zeroed();
        assert_eq!(sk_small.0.len(), 6_492);
        assert_eq!(sk_large.0.len(), 14_120);
    }
}
