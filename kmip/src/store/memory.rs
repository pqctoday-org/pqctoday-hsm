//! [`MemoryStore`] — in-memory [`KeyStore`] implementation for Phase 5
//! unit tests and dev sandbox runs. Phase 6 replaces this with the
//! SQLite-backed durable store.

use std::collections::HashMap;
use std::sync::RwLock;

use super::traits::{KeyStore, ObjectRecord};
use crate::error::{KmipError, Result};

pub struct MemoryStore {
    inner: RwLock<HashMap<String, ObjectRecord>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemoryStore {
    fn put(&self, record: ObjectRecord) -> Result<()> {
        let mut map = self.inner.write().expect("store poisoned");
        if map.contains_key(&record.uid) {
            return Err(KmipError::failed(
                crate::error::ResultReason::ObjectAlreadyExists,
                format!("UID {:?} already exists", record.uid),
            ));
        }
        map.insert(record.uid.clone(), record);
        Ok(())
    }

    fn get(&self, uid: &str) -> Result<Option<ObjectRecord>> {
        Ok(self
            .inner
            .read()
            .expect("store poisoned")
            .get(uid)
            .cloned())
    }

    fn update(&self, record: ObjectRecord) -> Result<()> {
        let mut map = self.inner.write().expect("store poisoned");
        if !map.contains_key(&record.uid) {
            return Err(KmipError::not_found(&record.uid));
        }
        map.insert(record.uid.clone(), record);
        Ok(())
    }

    fn remove(&self, uid: &str) -> Result<()> {
        self.inner
            .write()
            .expect("store poisoned")
            .remove(uid);
        Ok(())
    }

    fn find(&self, predicate: &dyn Fn(&ObjectRecord) -> bool) -> Result<Vec<ObjectRecord>> {
        Ok(self
            .inner
            .read()
            .expect("store poisoned")
            .values()
            .filter(|r| predicate(r))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
    use time::OffsetDateTime;

    fn rec(uid: &str) -> ObjectRecord {
        ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::PreActive,
            pkcs11_cka_id: vec![1, 2, 3],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        }
    }

    #[test]
    fn put_then_get() {
        let s = MemoryStore::new();
        s.put(rec("u1")).unwrap();
        let r = s.get("u1").unwrap().unwrap();
        assert_eq!(r.uid, "u1");
        assert!(s.get("missing").unwrap().is_none());
    }

    #[test]
    fn put_duplicate_fails() {
        let s = MemoryStore::new();
        s.put(rec("u1")).unwrap();
        let err = s.put(rec("u1")).unwrap_err();
        assert_eq!(
            err.result_reason(),
            crate::error::ResultReason::ObjectAlreadyExists
        );
    }

    #[test]
    fn update_requires_existing() {
        let s = MemoryStore::new();
        let err = s.update(rec("ghost")).unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ItemNotFound);
    }

    #[test]
    fn find_filters() {
        let s = MemoryStore::new();
        let mut a = rec("a");
        a.state = State::Active;
        let mut b = rec("b");
        b.state = State::Deactivated;
        s.put(a).unwrap();
        s.put(b).unwrap();
        let active = s.find(&|r| r.state == State::Active).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].uid, "a");
    }
}
