//! The default store: no persistence, matching the engine's behavior before
//! this module existed. Every method is the trait's default (no-op /
//! `None` / empty) — this type exists so [`super::active`] always has a
//! concrete backend to hand back, on every target including
//! `wasm32-unknown-unknown`.

pub struct MemoryStore;

impl super::TokenStore for MemoryStore {}
