//! Library half of `pqc-grpc-pkcs11`, split out so the WP5a acceptance
//! suite (`remoting/acceptance`) can construct a real
//! `Pkcs11RemoteService` and serve it in-process without going through the
//! binary's CLI/TLS bootstrap.

pub mod error;
pub mod service;
pub mod service_v32;
