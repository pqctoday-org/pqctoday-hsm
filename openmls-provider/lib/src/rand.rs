use std::sync::Arc;

use openmls_traits::random::OpenMlsRand;

use crate::backend::PkcsOps;
use crate::error::PqcTodayError;

/// HSM-backed RNG: every byte comes from `C_GenerateRandom` on the underlying
/// PKCS#11 token. softhsmv3 routes that to a SP 800-90A DRBG.
pub struct PqcTodayRand {
    pub(crate) ops: Arc<dyn PkcsOps>,
}

impl PqcTodayRand {
    pub fn new(ops: Arc<dyn PkcsOps>) -> Self {
        Self { ops }
    }
}

impl OpenMlsRand for PqcTodayRand {
    type Error = PqcTodayError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let v = self.ops.random(N)?;
        let mut buf = [0u8; N];
        buf.copy_from_slice(&v);
        Ok(buf)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.ops.random(len)
    }
}
