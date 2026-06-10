//! Multi-part cipher state machines for PKCS#11 v3.2 `C_EncryptUpdate` /
//! `C_EncryptFinal` and the matching Decrypt pair.
//!
//! Single-shot `C_Encrypt` and `C_Decrypt` live in [`crate::ffi`] and use
//! the high-level `aes-gcm` / `cbc` / `ctr` crates that finalise in one
//! call. Multi-part requires per-call state — buffered partial blocks for
//! the block modes, an advancing counter for CTR/GCM, and incremental
//! GHASH for GCM authentication. This module owns that state.
//!
//! Spec mapping (PKCS#11 v3.2):
//!
//! - §5.2.6 `C_EncryptUpdate` — feed a part, get a ciphertext part
//! - §5.2.7 `C_EncryptFinal` — flush buffered bytes, emit tag for AEAD
//! - §5.2.10 `C_DecryptUpdate` — feed a ciphertext part, get plaintext
//! - §5.2.11 `C_DecryptFinal` — flush + verify AEAD tag
//!
//! Mechanism mapping:
//!
//! | Mech | Update behaviour | Final behaviour |
//! |---|---|---|
//! | `CKM_AES_ECB` (§6.27.2)     | emit full blocks; buffer `<16` residue | error if residue non-empty |
//! | `CKM_AES_CBC` (§6.27.3)     | emit full blocks + CBC chain | error if residue non-empty |
//! | `CKM_AES_CBC_PAD` (§6.27.4) | encrypt: as CBC; decrypt: hold back last full block | emit/strip PKCS#7 pad |
//! | `CKM_AES_CTR` (§6.27.5)     | byte stream, no buffering | empty output |
//! | `CKM_AES_GCM` (§6.27.7)     | byte stream + GHASH; decrypt holds back tag | emit/verify auth tag |
//!
//! Length prediction (`update_len` / `final_len`) backs the PKCS#11 §5.2
//! two-pass convention: a call with a NULL output pointer returns the
//! required size without consuming input or advancing state. For decrypt
//! finalisation the prediction is an upper bound, which §5.2 explicitly
//! permits ("the size may be somewhat larger than precisely needed").

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
// `aes::cipher::KeyInit` above is the same `crypto_common::KeyInit` trait
// that `GHash::new` needs, so no separate universal-hash import.
use ghash::{GHash, universal_hash::UniversalHash};
use subtle::ConstantTimeEq;

use crate::constants::{
    CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
};

const BLOCK: usize = 16;

/// AES variant — folds the three key-size types into one enum so the
/// state machines stay monomorphic over key length.
pub enum AesKey {
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
}

impl AesKey {
    /// Construct from a raw key. Returns `None` for unsupported lengths.
    pub fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Some(AesKey::Aes128(aes::Aes128::new(GenericArray::from_slice(key)))),
            24 => Some(AesKey::Aes192(aes::Aes192::new(GenericArray::from_slice(key)))),
            32 => Some(AesKey::Aes256(aes::Aes256::new(GenericArray::from_slice(key)))),
            _ => None,
        }
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        let ga = GenericArray::from_mut_slice(block);
        match self {
            AesKey::Aes128(c) => c.encrypt_block(ga),
            AesKey::Aes192(c) => c.encrypt_block(ga),
            AesKey::Aes256(c) => c.encrypt_block(ga),
        }
    }

    fn decrypt_block(&self, block: &mut [u8; BLOCK]) {
        let ga = GenericArray::from_mut_slice(block);
        match self {
            AesKey::Aes128(c) => c.decrypt_block(ga),
            AesKey::Aes192(c) => c.decrypt_block(ga),
            AesKey::Aes256(c) => c.decrypt_block(ga),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CipherDirection {
    Encrypt,
    Decrypt,
}

impl CipherDirection {
    /// PKCS#11 v3.2 §6.16 — bad input length is `CKR_DATA_LEN_RANGE` on
    /// the encrypt side and `CKR_ENCRYPTED_DATA_LEN_RANGE` on decrypt.
    fn len_range_error(self) -> u32 {
        match self {
            CipherDirection::Encrypt => CKR_DATA_LEN_RANGE,
            CipherDirection::Decrypt => CKR_ENCRYPTED_DATA_LEN_RANGE,
        }
    }
}

/// One active multi-part cipher op. PKCS#11 v3.2 §5.6 limits each session
/// to at most one active encrypt op and one decrypt op, so exactly one of
/// these is stashed per session per direction.
pub enum MultipartCipher {
    Ecb(EcbState),
    Cbc(CbcState),
    CbcPad(CbcPadState),
    Ctr(CtrState),
    Gcm(GcmState),
}

impl MultipartCipher {
    /// Output size the next `update(part)` of `part_len` bytes will
    /// produce. Pure prediction — does not mutate state.
    pub fn update_len(&self, part_len: usize) -> usize {
        match self {
            MultipartCipher::Ecb(s) => full_blocks(s.buf.len() + part_len),
            MultipartCipher::Cbc(s) => full_blocks(s.buf.len() + part_len),
            MultipartCipher::CbcPad(s) => s.update_len(part_len),
            MultipartCipher::Ctr(_) => part_len,
            MultipartCipher::Gcm(s) => s.update_len(part_len),
        }
    }

    /// Upper bound on the output size of `finalize()`. Exact for all
    /// modes except CBC_PAD decrypt, where the stripped-padding length is
    /// unknowable before decryption (§5.2 permits over-estimates).
    pub fn final_len(&self) -> usize {
        match self {
            MultipartCipher::Ecb(_) | MultipartCipher::Cbc(_) | MultipartCipher::Ctr(_) => 0,
            MultipartCipher::CbcPad(_) => BLOCK,
            MultipartCipher::Gcm(s) => match s.dir {
                CipherDirection::Encrypt => s.tag_len,
                CipherDirection::Decrypt => 0,
            },
        }
    }

    /// Drive the state machine with a chunk of input. Returns the bytes
    /// to hand back to the caller for this part (may be empty while the
    /// input sits below a block / hold-back boundary).
    pub fn update(&mut self, part: &[u8]) -> Result<Vec<u8>, u32> {
        match self {
            MultipartCipher::Ecb(s) => Ok(s.update(part)),
            MultipartCipher::Cbc(s) => Ok(s.update(part)),
            MultipartCipher::CbcPad(s) => Ok(s.update(part)),
            MultipartCipher::Ctr(s) => Ok(s.update(part)),
            MultipartCipher::Gcm(s) => Ok(s.update(part)),
        }
    }

    /// Flush buffered input, emit/strip padding, and emit/verify the
    /// AEAD tag. Consumes the operation per §5.2.7 / §5.2.11.
    pub fn finalize(self) -> Result<Vec<u8>, u32> {
        match self {
            MultipartCipher::Ecb(s) => s.finalize(),
            MultipartCipher::Cbc(s) => s.finalize(),
            MultipartCipher::CbcPad(s) => s.finalize(),
            MultipartCipher::Ctr(_) => Ok(Vec::new()),
            MultipartCipher::Gcm(s) => s.finalize(),
        }
    }
}

fn full_blocks(len: usize) -> usize {
    len / BLOCK * BLOCK
}

// ── ECB (§6.27.2) ────────────────────────────────────────────────────────────

pub struct EcbState {
    key: AesKey,
    dir: CipherDirection,
    buf: Vec<u8>,
}

impl EcbState {
    pub fn new(key: AesKey, dir: CipherDirection) -> Self {
        Self { key, dir, buf: Vec::new() }
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(part);
        let take = full_blocks(self.buf.len());
        let mut out: Vec<u8> = self.buf.drain(..take).collect();
        for chunk in out.chunks_exact_mut(BLOCK) {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(chunk);
            match self.dir {
                CipherDirection::Encrypt => self.key.encrypt_block(&mut block),
                CipherDirection::Decrypt => self.key.decrypt_block(&mut block),
            }
            chunk.copy_from_slice(&block);
        }
        out
    }

    fn finalize(self) -> Result<Vec<u8>, u32> {
        // §6.27.2 — plain ECB has no padding; a residue means the total
        // input was not a block multiple.
        if !self.buf.is_empty() {
            return Err(self.dir.len_range_error());
        }
        Ok(Vec::new())
    }
}

// ── CBC raw (§6.27.3) ────────────────────────────────────────────────────────

pub struct CbcState {
    key: AesKey,
    dir: CipherDirection,
    iv: [u8; BLOCK],
    buf: Vec<u8>,
}

impl CbcState {
    pub fn new(key: AesKey, iv: [u8; BLOCK], dir: CipherDirection) -> Self {
        Self { key, dir, iv, buf: Vec::new() }
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(part);
        let take = full_blocks(self.buf.len());
        let consumed: Vec<u8> = self.buf.drain(..take).collect();
        let mut out = Vec::with_capacity(consumed.len());
        for chunk in consumed.chunks_exact(BLOCK) {
            let mut block = [0u8; BLOCK];
            match self.dir {
                CipherDirection::Encrypt => {
                    for i in 0..BLOCK {
                        block[i] = chunk[i] ^ self.iv[i];
                    }
                    self.key.encrypt_block(&mut block);
                    self.iv = block;
                }
                CipherDirection::Decrypt => {
                    block.copy_from_slice(chunk);
                    self.key.decrypt_block(&mut block);
                    for i in 0..BLOCK {
                        block[i] ^= self.iv[i];
                    }
                    self.iv.copy_from_slice(chunk);
                }
            }
            out.extend_from_slice(&block);
        }
        out
    }

    fn finalize(self) -> Result<Vec<u8>, u32> {
        if !self.buf.is_empty() {
            return Err(self.dir.len_range_error());
        }
        Ok(Vec::new())
    }
}

// ── CBC with PKCS#7 padding (§6.27.4) ────────────────────────────────────────

pub struct CbcPadState {
    inner: CbcState,
    /// Decrypt only: ciphertext withheld from `inner`. The final full
    /// block carries the padding and must not be released before
    /// `finalize` — so when the buffered length is an exact block
    /// multiple, one block stays behind.
    holdback: Vec<u8>,
}

impl CbcPadState {
    pub fn new(key: AesKey, iv: [u8; BLOCK], dir: CipherDirection) -> Self {
        Self { inner: CbcState::new(key, iv, dir), holdback: Vec::new() }
    }

    fn update_len(&self, part_len: usize) -> usize {
        match self.inner.dir {
            CipherDirection::Encrypt => full_blocks(self.inner.buf.len() + part_len),
            CipherDirection::Decrypt => releasable(self.holdback.len() + part_len),
        }
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        match self.inner.dir {
            CipherDirection::Encrypt => self.inner.update(part),
            CipherDirection::Decrypt => {
                self.holdback.extend_from_slice(part);
                let take = releasable(self.holdback.len());
                let release: Vec<u8> = self.holdback.drain(..take).collect();
                self.inner.update(&release)
            }
        }
    }

    fn finalize(mut self) -> Result<Vec<u8>, u32> {
        match self.inner.dir {
            CipherDirection::Encrypt => {
                // §6.27.4 — PKCS#7: always append 1..=16 pad bytes, so
                // the residue (0..=15 bytes) closes to exactly one block.
                let pad = BLOCK - self.inner.buf.len() % BLOCK;
                let out = self.inner.update(&vec![pad as u8; pad]);
                debug_assert_eq!(out.len(), BLOCK);
                Ok(out)
            }
            CipherDirection::Decrypt => {
                // After update() the hold-back is either exactly one block
                // (the pad block) or a length that can't end a valid
                // CBC_PAD ciphertext (empty, or not a block multiple).
                if self.holdback.len() != BLOCK {
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
                }
                let last = std::mem::take(&mut self.holdback);
                let mut pt = self.inner.update(&last);
                debug_assert_eq!(pt.len(), BLOCK);
                let pad = pt[BLOCK - 1] as usize;
                if pad == 0 || pad > BLOCK || pt[BLOCK - pad..].iter().any(|&b| b != pad as u8) {
                    return Err(CKR_ENCRYPTED_DATA_INVALID);
                }
                pt.truncate(BLOCK - pad);
                Ok(pt)
            }
        }
    }
}

/// How many of `total` buffered ciphertext bytes may be released while
/// still retaining a candidate final (padding-carrying) block.
fn releasable(total: usize) -> usize {
    if total % BLOCK == 0 {
        total.saturating_sub(BLOCK)
    } else {
        full_blocks(total)
    }
}

// ── CTR (§6.27.5) ────────────────────────────────────────────────────────────

/// Big-endian 128-bit counter mode, matching `ctr::Ctr128BE` (and thus
/// the single-shot `C_Encrypt` path): the whole counter block increments,
/// not just the low `ulCounterBits`.
pub struct CtrState {
    key: AesKey,
    counter: [u8; BLOCK],
    keystream: [u8; BLOCK],
    /// Read offset into `keystream`; `BLOCK` means exhausted.
    ks_pos: usize,
}

impl CtrState {
    pub fn new(key: AesKey, counter_block: [u8; BLOCK]) -> Self {
        Self { key, counter: counter_block, keystream: [0u8; BLOCK], ks_pos: BLOCK }
    }

    fn next_keystream_byte(&mut self) -> u8 {
        if self.ks_pos == BLOCK {
            self.keystream = self.counter;
            self.key.encrypt_block(&mut self.keystream);
            inc_be(&mut self.counter, BLOCK);
            self.ks_pos = 0;
        }
        let b = self.keystream[self.ks_pos];
        self.ks_pos += 1;
        b
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        part.iter().map(|&b| b ^ self.next_keystream_byte()).collect()
    }
}

/// Increment the trailing `width` bytes of `block` as a big-endian
/// counter (wrapping). `width == 16` gives CTR-128; `width == 4` gives
/// the 32-bit GCM counter increment of NIST SP 800-38D §6.2.
fn inc_be(block: &mut [u8; BLOCK], width: usize) {
    for i in (BLOCK - width..BLOCK).rev() {
        block[i] = block[i].wrapping_add(1);
        if block[i] != 0 {
            break;
        }
    }
}

// ── GCM (§6.27.7, NIST SP 800-38D) ───────────────────────────────────────────

pub struct GcmState {
    key: AesKey,
    dir: CipherDirection,
    /// Incremental GHASH over AAD (fed at construction) then ciphertext.
    ghash: GHash,
    /// Partial ciphertext block not yet fed to `ghash` (len < 16).
    ghash_buf: Vec<u8>,
    /// CTR-32 counter for the payload keystream (starts at inc32(J0)).
    counter: [u8; BLOCK],
    keystream: [u8; BLOCK],
    ks_pos: usize,
    /// E_K(J0) — XORed with the GHASH output to form the tag.
    ek_j0: [u8; BLOCK],
    aad_len: u64,
    ct_len: u64,
    tag_len: usize,
    /// Decrypt only: trailing `tag_len` bytes of input withheld, since
    /// the ciphertext/tag boundary is unknowable before `finalize`.
    pending: Vec<u8>,
}

impl GcmState {
    /// `iv` must be the 96-bit nonce (enforced at `C_EncryptInit`);
    /// `tag_bits` of 0 defaults to a full 128-bit tag.
    pub fn new(
        key: AesKey,
        iv: &[u8; 12],
        aad: &[u8],
        tag_bits: u32,
        dir: CipherDirection,
    ) -> Self {
        // H = E_K(0^128) keys GHASH (SP 800-38D §7.1 step 1).
        let mut h = [0u8; BLOCK];
        key.encrypt_block(&mut h);
        let mut ghash = GHash::new(GenericArray::from_slice(&h));
        ghash.update_padded(aad);

        // J0 = IV || 0^31 || 1 for the 96-bit IV path (§7.1 step 2).
        let mut j0 = [0u8; BLOCK];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        let mut ek_j0 = j0;
        key.encrypt_block(&mut ek_j0);
        let mut counter = j0;
        inc_be(&mut counter, 4);

        let tag_len = match tag_bits {
            0 => BLOCK,
            bits => ((bits as usize) / 8).clamp(4, BLOCK),
        };
        Self {
            key,
            dir,
            ghash,
            ghash_buf: Vec::new(),
            counter,
            keystream: [0u8; BLOCK],
            ks_pos: BLOCK,
            ek_j0,
            aad_len: aad.len() as u64,
            ct_len: 0,
            tag_len,
            pending: Vec::new(),
        }
    }

    fn update_len(&self, part_len: usize) -> usize {
        match self.dir {
            CipherDirection::Encrypt => part_len,
            // Everything past the withheld tag-sized tail is released.
            CipherDirection::Decrypt => {
                (self.pending.len() + part_len).saturating_sub(self.tag_len)
            }
        }
    }

    fn next_keystream_byte(&mut self) -> u8 {
        if self.ks_pos == BLOCK {
            self.keystream = self.counter;
            self.key.encrypt_block(&mut self.keystream);
            inc_be(&mut self.counter, 4);
            self.ks_pos = 0;
        }
        let b = self.keystream[self.ks_pos];
        self.ks_pos += 1;
        b
    }

    fn ghash_feed(&mut self, byte: u8) {
        self.ghash_buf.push(byte);
        if self.ghash_buf.len() == BLOCK {
            self.ghash.update(&[*GenericArray::from_slice(&self.ghash_buf)]);
            self.ghash_buf.clear();
        }
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        match self.dir {
            CipherDirection::Encrypt => {
                let mut out = Vec::with_capacity(part.len());
                for &pt in part {
                    let ct = pt ^ self.next_keystream_byte();
                    self.ghash_feed(ct);
                    out.push(ct);
                }
                self.ct_len += part.len() as u64;
                out
            }
            CipherDirection::Decrypt => {
                self.pending.extend_from_slice(part);
                let take = self.pending.len().saturating_sub(self.tag_len);
                let release: Vec<u8> = self.pending.drain(..take).collect();
                let mut out = Vec::with_capacity(release.len());
                for &ct in &release {
                    self.ghash_feed(ct);
                    out.push(ct ^ self.next_keystream_byte());
                }
                self.ct_len += release.len() as u64;
                out
            }
        }
    }

    /// GHASH(padded CT || len64(AAD) || len64(CT)) XOR E_K(J0), truncated
    /// to `tag_len` (SP 800-38D §7.1 steps 5–8).
    fn compute_tag(mut self) -> Vec<u8> {
        if !self.ghash_buf.is_empty() {
            let mut last = [0u8; BLOCK];
            last[..self.ghash_buf.len()].copy_from_slice(&self.ghash_buf);
            self.ghash.update(&[last.into()]);
        }
        let mut len_block = [0u8; BLOCK];
        len_block[..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(self.ct_len * 8).to_be_bytes());
        self.ghash.update(&[len_block.into()]);
        let s = self.ghash.finalize();
        let mut tag: Vec<u8> = self.ek_j0.iter().zip(s.iter()).map(|(a, b)| a ^ b).collect();
        tag.truncate(self.tag_len);
        tag
    }

    fn finalize(mut self) -> Result<Vec<u8>, u32> {
        match self.dir {
            CipherDirection::Encrypt => Ok(self.compute_tag()),
            CipherDirection::Decrypt => {
                // The withheld tail must be exactly the tag; shorter total
                // input cannot have carried one.
                if self.pending.len() != self.tag_len {
                    return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
                }
                let received = std::mem::take(&mut self.pending);
                let expected = self.compute_tag();
                if bool::from(expected.ct_eq(&received)) {
                    Ok(Vec::new())
                } else {
                    Err(CKR_ENCRYPTED_DATA_INVALID)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Feed `data` through `update` in chunks of `sizes` (cycled), then
    /// finalize, returning the concatenated output. Also asserts the
    /// `update_len` / `final_len` predictions along the way.
    fn drive(mut mp: MultipartCipher, data: &[u8], sizes: &[usize]) -> Result<Vec<u8>, u32> {
        let mut out = Vec::new();
        let mut off = 0;
        let mut i = 0;
        while off < data.len() {
            let n = sizes[i % sizes.len()].clamp(1, data.len() - off);
            let expect = mp.update_len(n);
            let part = mp.update(&data[off..off + n])?;
            assert_eq!(part.len(), expect, "update_len prediction mismatch");
            out.extend_from_slice(&part);
            off += n;
            i += 1;
        }
        let bound = mp.final_len();
        let last = mp.finalize()?;
        assert!(last.len() <= bound, "final_len must be an upper bound");
        out.extend_from_slice(&last);
        Ok(out)
    }

    const CHUNKINGS: &[&[usize]] = &[&[1], &[7, 3], &[16], &[33, 1, 5], &[64]];

    // NIST SP 800-38A F.1.1 — ECB-AES128.Encrypt, block 1.
    #[test]
    fn ecb_kat_sp800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let ct = hex("3ad77bb40d7a3660a89ecaf32466ef97");
        for sizes in CHUNKINGS {
            let enc = MultipartCipher::Ecb(EcbState::new(
                AesKey::new(&key).unwrap(),
                CipherDirection::Encrypt,
            ));
            assert_eq!(drive(enc, &pt, sizes).unwrap(), ct);
            let dec = MultipartCipher::Ecb(EcbState::new(
                AesKey::new(&key).unwrap(),
                CipherDirection::Decrypt,
            ));
            assert_eq!(drive(dec, &ct, sizes).unwrap(), pt);
        }
    }

    #[test]
    fn ecb_residue_is_len_range_error() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let mut enc = MultipartCipher::Ecb(EcbState::new(
            AesKey::new(&key).unwrap(),
            CipherDirection::Encrypt,
        ));
        enc.update(&[0u8; 5]).unwrap();
        assert_eq!(enc.finalize().unwrap_err(), CKR_DATA_LEN_RANGE);
        let mut dec = MultipartCipher::Ecb(EcbState::new(
            AesKey::new(&key).unwrap(),
            CipherDirection::Decrypt,
        ));
        dec.update(&[0u8; 17]).unwrap();
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_LEN_RANGE);
    }

    // NIST SP 800-38A F.2.1 — CBC-AES128.Encrypt, blocks 1–2.
    #[test]
    fn cbc_kat_sp800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
        for sizes in CHUNKINGS {
            let enc = MultipartCipher::Cbc(CbcState::new(
                AesKey::new(&key).unwrap(),
                iv,
                CipherDirection::Encrypt,
            ));
            assert_eq!(drive(enc, &pt, sizes).unwrap(), ct);
            let dec = MultipartCipher::Cbc(CbcState::new(
                AesKey::new(&key).unwrap(),
                iv,
                CipherDirection::Decrypt,
            ));
            assert_eq!(drive(dec, &ct, sizes).unwrap(), pt);
        }
    }

    /// CBC_PAD must round-trip arbitrary lengths and match the one-shot
    /// `cbc` crate ciphertext (the single-shot `C_Encrypt` path).
    #[test]
    fn cbc_pad_round_trip_matches_one_shot() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        for pt_len in [0usize, 1, 15, 16, 17, 31, 32, 100] {
            let pt: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();
            let padded_len = pt.len() + BLOCK - pt.len() % BLOCK;
            let mut buf = vec![0u8; padded_len];
            buf[..pt.len()].copy_from_slice(&pt);
            let one_shot = cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
                .unwrap()
                .to_vec();
            for sizes in CHUNKINGS {
                let enc = MultipartCipher::CbcPad(CbcPadState::new(
                    AesKey::new(&key).unwrap(),
                    iv,
                    CipherDirection::Encrypt,
                ));
                let ct = drive(enc, &pt, sizes).unwrap();
                assert_eq!(ct, one_shot, "pt_len={pt_len} sizes={sizes:?}");
                let dec = MultipartCipher::CbcPad(CbcPadState::new(
                    AesKey::new(&key).unwrap(),
                    iv,
                    CipherDirection::Decrypt,
                ));
                assert_eq!(drive(dec, &ct, sizes).unwrap(), pt, "pt_len={pt_len}");
            }
        }
    }

    #[test]
    fn cbc_pad_decrypt_rejects_bad_input() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = [0u8; 16];
        // Not a block multiple → length error.
        let mut dec = MultipartCipher::CbcPad(CbcPadState::new(
            AesKey::new(&key).unwrap(),
            iv,
            CipherDirection::Decrypt,
        ));
        dec.update(&[0u8; 20]).unwrap();
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_LEN_RANGE);
        // Empty ciphertext → length error (CBC_PAD output is never empty).
        let dec = MultipartCipher::CbcPad(CbcPadState::new(
            AesKey::new(&key).unwrap(),
            iv,
            CipherDirection::Decrypt,
        ));
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_LEN_RANGE);
        // Garbage block → invalid padding.
        let mut dec = MultipartCipher::CbcPad(CbcPadState::new(
            AesKey::new(&key).unwrap(),
            iv,
            CipherDirection::Decrypt,
        ));
        dec.update(&[0xAAu8; 16]).unwrap();
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);
    }

    // NIST SP 800-38A F.5.1 — CTR-AES128.Encrypt, blocks 1–2.
    #[test]
    fn ctr_kat_sp800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let cb: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
        for sizes in CHUNKINGS {
            let enc = MultipartCipher::Ctr(CtrState::new(AesKey::new(&key).unwrap(), cb));
            assert_eq!(drive(enc, &pt, sizes).unwrap(), ct);
            // CTR is its own inverse.
            let dec = MultipartCipher::Ctr(CtrState::new(AesKey::new(&key).unwrap(), cb));
            assert_eq!(drive(dec, &ct, sizes).unwrap(), pt);
        }
    }

    // GCM validation vector (McGrew–Viega test case 3): AES-128, 96-bit
    // IV, 64-byte plaintext, no AAD.
    #[test]
    fn gcm_kat_no_aad() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        );
        let tag = hex("4d5c2af327cd64a62cf35abd2ba6fab4");
        run_gcm_kat(&key, &iv, &[], &pt, &ct, &tag);
    }

    // Same set, test case 4: 60-byte plaintext + 20-byte AAD.
    #[test]
    fn gcm_kat_with_aad() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let tag = hex("5bc94fbc3221a5db94fae95ae7121a47");
        run_gcm_kat(&key, &iv, &aad, &pt, &ct, &tag);
    }

    fn run_gcm_kat(key: &[u8], iv: &[u8; 12], aad: &[u8], pt: &[u8], ct: &[u8], tag: &[u8]) {
        let mut ct_tag = ct.to_vec();
        ct_tag.extend_from_slice(tag);
        for sizes in CHUNKINGS {
            let enc = MultipartCipher::Gcm(GcmState::new(
                AesKey::new(key).unwrap(),
                iv,
                aad,
                128,
                CipherDirection::Encrypt,
            ));
            assert_eq!(drive(enc, pt, sizes).unwrap(), ct_tag, "sizes={sizes:?}");
            let dec = MultipartCipher::Gcm(GcmState::new(
                AesKey::new(key).unwrap(),
                iv,
                aad,
                128,
                CipherDirection::Decrypt,
            ));
            assert_eq!(drive(dec, &ct_tag, sizes).unwrap(), pt, "sizes={sizes:?}");
        }
    }

    /// Streaming GCM must agree with the one-shot `aes-gcm` crate (the
    /// single-shot `C_Encrypt` path) for AES-256 as well.
    #[test]
    fn gcm_matches_one_shot_crate_aes256() {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit as GcmKeyInit};
        let key = [0x42u8; 32];
        let iv = [0x24u8; 12];
        let aad = b"header bytes";
        let pt: Vec<u8> = (0..123u8).collect();
        let one_shot = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(aes_gcm::Nonce::from_slice(&iv), Payload { msg: &pt, aad })
            .unwrap();
        let enc = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            aad,
            128,
            CipherDirection::Encrypt,
        ));
        assert_eq!(drive(enc, &pt, &[13, 1, 40]).unwrap(), one_shot);
    }

    #[test]
    fn gcm_decrypt_detects_tampering_and_short_input() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let pt = b"attack at dawn".to_vec();
        let mut enc = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            &[],
            128,
            CipherDirection::Encrypt,
        ));
        let mut ct = enc.update(&pt).unwrap();
        ct.extend_from_slice(&enc.finalize().unwrap());

        // Flip one ciphertext bit → tag verification must fail.
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        let mut dec = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            &[],
            128,
            CipherDirection::Decrypt,
        ));
        dec.update(&tampered).unwrap();
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);

        // Input shorter than the tag → length error.
        let mut dec = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            &[],
            128,
            CipherDirection::Decrypt,
        ));
        dec.update(&ct[..8]).unwrap();
        assert_eq!(dec.finalize().unwrap_err(), CKR_ENCRYPTED_DATA_LEN_RANGE);
    }

    /// AES-192 streams correctly (the one-shot path only handles 128/256,
    /// so this is covered by an encrypt/decrypt round-trip) and 96-bit
    /// truncated tags are honoured.
    #[test]
    fn gcm_aes192_round_trip_truncated_tag() {
        let key = [0x11u8; 24];
        let iv = [0x05u8; 12];
        let pt: Vec<u8> = (0..77u8).collect();
        let mut enc = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            b"aad",
            96,
            CipherDirection::Encrypt,
        ));
        let mut ct = enc.update(&pt).unwrap();
        let tag = enc.finalize().unwrap();
        assert_eq!(tag.len(), 12); // 96-bit truncated tag
        ct.extend_from_slice(&tag);
        let mut dec = MultipartCipher::Gcm(GcmState::new(
            AesKey::new(&key).unwrap(),
            &iv,
            b"aad",
            96,
            CipherDirection::Decrypt,
        ));
        let mut out = dec.update(&ct).unwrap();
        out.extend_from_slice(&dec.finalize().unwrap());
        assert_eq!(out, pt);
    }
}
