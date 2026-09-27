//! Test-only deterministic RNG (`#[cfg(test)]` only — never shipped, never used to
//! generate a real key). NOT cryptographically secure; exists purely so unit tests
//! across this crate don't each need their own throwaway RNG type or an extra
//! dev-dependency. Production keygen always uses a real `CryptoRng` supplied by the
//! caller (the PKCS#11 engine passes `rand::rngs::OsRng` at the FFI boundary).

#![cfg(test)]

use rand::{CryptoRng, RngCore};

pub(crate) struct XorShiftRng(u64);

impl XorShiftRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
}

impl RngCore for XorShiftRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Test-only marker impl — not a security claim; see the module doc.
impl CryptoRng for XorShiftRng {}
