//! Authenticated connection metadata for the request being dispatched on this thread
//! (admin/ceremony addendum §5, A-16).
//!
//! The TLS listener knows the client certificate and its own address; the PKCS#11 operation
//! handlers below it do not. The listener enters a [`Scope`] around the synchronous dispatch, and
//! the replication admin binding reads [`current`] to build the application context the engine
//! stamps into its audit lines. Dispatch runs to completion on the one blocking-pool thread, so a
//! thread-local is exact; any other thread sees `None`.

use std::cell::RefCell;

use sha2::Digest;

/// What the transport authenticated about the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnMeta {
    /// SHA-256 of the DER of the client's leaf certificate.
    pub client_cert_sha256: [u8; 32],
    /// The local address the connection arrived on.
    pub listener: String,
}

impl ConnMeta {
    pub fn from_leaf(leaf_der: &[u8], listener: String) -> Self {
        Self { client_cert_sha256: sha2::Sha256::digest(leaf_der).into(), listener }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<ConnMeta>> = const { RefCell::new(None) };
}

/// Restores the previous value when dropped.
pub struct Scope(Option<ConnMeta>);

/// Make `meta` the current connection metadata on this thread until the returned guard drops.
pub fn enter(meta: Option<ConnMeta>) -> Scope {
    Scope(CURRENT.with(|c| c.replace(meta)))
}

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.0.take());
    }
}

/// The metadata of the connection being served on this thread, if any.
pub fn current() -> Option<ConnMeta> {
    CURRENT.with(|c| c.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_sha256_of_the_leaf_der() {
        let m = ConnMeta::from_leaf(b"leaf-der", "10.0.0.1:5696".into());
        assert_eq!(m.client_cert_sha256, <[u8; 32]>::from(sha2::Sha256::digest(b"leaf-der")));
        assert_ne!(m.client_cert_sha256, [0u8; 32]);
    }

    #[test]
    fn scope_sets_nests_and_restores() {
        assert!(current().is_none());
        let a = ConnMeta::from_leaf(b"a", "a:1".into());
        let b = ConnMeta::from_leaf(b"b", "b:2".into());
        {
            let _outer = enter(Some(a.clone()));
            assert_eq!(current(), Some(a.clone()));
            {
                let _inner = enter(Some(b.clone()));
                assert_eq!(current(), Some(b));
            }
            assert_eq!(current(), Some(a), "inner scope restored the outer value");
        }
        assert!(current().is_none(), "outer scope restored the empty value");
    }

    #[test]
    fn other_threads_do_not_see_it() {
        let _s = enter(Some(ConnMeta::from_leaf(b"x", "x:1".into())));
        assert!(std::thread::spawn(current).join().unwrap().is_none());
    }
}
