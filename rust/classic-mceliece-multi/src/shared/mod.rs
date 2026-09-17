//! Code genuinely shared across all 10 (or, where noted per-file, most of the 10)
//! Classic McEliece parameter sets. See each submodule's own doc comment for its
//! exact sharing granularity (some are fully shared, some split narrow/wide, one —
//! `sk_gen` — splits into the same 4-way family `gf::gf_mul_inplace_*` uses).

pub(crate) mod benes;
pub(crate) mod bm;
pub(crate) mod controlbits;
pub(crate) mod crypto_hash;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod gf;
pub(crate) mod int32_sort;
pub(crate) mod operations;
pub(crate) mod pk_gen;
pub(crate) mod root;
pub(crate) mod sk_gen;
pub(crate) mod synd;
pub(crate) mod transpose;
pub(crate) mod uint64_sort;
pub(crate) mod util;
