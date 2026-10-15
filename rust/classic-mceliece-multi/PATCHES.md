# Changes to this fork of `classic-mceliece-rust` 3.1.0

Upstream: https://github.com/Colfenor/classic-mceliece-rust, version 3.1.0,
commit `6e5ce0cbba807e5288b677cee07224a8e30a0876`, MIT (`LICENSE.txt`, kept
unchanged). `UPSTREAM-CHANGELOG.md` is upstream's `CHANGELOG.md`.

Changed by PQC Today, LLC, 2026-09-09 onwards: the crate is restructured so
that all 10 Classic McEliece parameter sets compile into one build instead of
one parameter set per Cargo feature (field arithmetic, Beneš network and
sizes become per-parameter-set code). `README.md` describes the structure;
`git log -- rust/classic-mceliece-multi` gives every change and its date.
