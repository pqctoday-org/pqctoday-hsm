//! Library half of `pqc-rest-pkcs11`, split out so the WP5a acceptance
//! suite (`remoting/acceptance`) can construct a real axum `Router` and
//! serve it in-process without going through the binary's CLI/TLS
//! bootstrap.

pub mod dto;
pub mod dto_v32;
pub mod error;
pub mod routes;
pub mod routes_v32;
