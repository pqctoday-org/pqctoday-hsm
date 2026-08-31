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
use zeroize::Zeroize;

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
    Ofb(OfbState),
    Cfb128(Cfb128State),
    Cfb8(Cfb8State),
    Cfb1(Cfb1State),
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
            MultipartCipher::Ofb(_) => part_len,
            MultipartCipher::Cfb128(s) => full_blocks(s.buf.len() + part_len),
            MultipartCipher::Cfb8(_) => part_len,
            MultipartCipher::Cfb1(_) => part_len,
            MultipartCipher::Gcm(s) => s.update_len(part_len),
        }
    }

    /// Upper bound on the output size of `finalize()`. Exact for all
    /// modes except CBC_PAD decrypt, where the stripped-padding length is
    /// unknowable before decryption (§5.2 permits over-estimates).
    pub fn final_len(&self) -> usize {
        match self {
            MultipartCipher::Ecb(_)
            | MultipartCipher::Cbc(_)
            | MultipartCipher::Ctr(_)
            | MultipartCipher::Ofb(_)
            | MultipartCipher::Cfb8(_)
            | MultipartCipher::Cfb1(_) => 0,
            MultipartCipher::CbcPad(_) => BLOCK,
            // Exact: `finalize()` emits precisely the buffered short final
            // segment, same convention as CbcPad's exact-except-decrypt note.
            MultipartCipher::Cfb128(s) => s.buf.len(),
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
            MultipartCipher::Ofb(s) => Ok(s.update(part)),
            MultipartCipher::Cfb128(s) => Ok(s.update(part)),
            MultipartCipher::Cfb8(s) => Ok(s.update(part)),
            MultipartCipher::Cfb1(s) => Ok(s.update(part)),
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
            MultipartCipher::Ofb(_) => Ok(Vec::new()),
            MultipartCipher::Cfb128(s) => Ok(s.finalize()),
            MultipartCipher::Cfb8(_) => Ok(Vec::new()),
            MultipartCipher::Cfb1(_) => Ok(Vec::new()),
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

/// Big-endian counter mode. By default the whole 128-bit block increments
/// (matching `ctr::Ctr128BE`); `new_with_width` restricts the increment to
/// the low `counter_width` bytes per CK_AES_CTR_PARAMS.ulCounterBits
/// (PKCS#11 v3.2 §6.27.6 — the counter wraps within ulCounterBits).
pub struct CtrState {
    key: AesKey,
    counter: [u8; BLOCK],
    keystream: [u8; BLOCK],
    /// Read offset into `keystream`; `BLOCK` means exhausted.
    ks_pos: usize,
    /// Bytes of the block that increment (1..=16).
    counter_width: usize,
}

impl CtrState {
    pub fn new(key: AesKey, counter_block: [u8; BLOCK]) -> Self {
        Self::new_with_width(key, counter_block, BLOCK)
    }

    /// `width_bytes` = ulCounterBits / 8 (engine restriction: ulCounterBits
    /// must be a byte multiple; validated at C_EncryptInit).
    pub fn new_with_width(key: AesKey, counter_block: [u8; BLOCK], width_bytes: usize) -> Self {
        Self {
            key,
            counter: counter_block,
            keystream: [0u8; BLOCK],
            ks_pos: BLOCK,
            counter_width: width_bytes.clamp(1, BLOCK),
        }
    }

    fn next_keystream_byte(&mut self) -> u8 {
        if self.ks_pos == BLOCK {
            self.keystream = self.counter;
            self.key.encrypt_block(&mut self.keystream);
            inc_be(&mut self.counter, self.counter_width);
            self.ks_pos = 0;
        }
        let b = self.keystream[self.ks_pos];
        self.ks_pos += 1;
        b
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        part.iter().map(|&b| b ^ self.next_keystream_byte()).collect()
    }

    /// One-shot helper for the single-part C_Encrypt/C_Decrypt paths.
    pub fn update_public(&mut self, part: &[u8]) -> Vec<u8> {
        self.update(part)
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

// ── OFB (§6.11, NIST SP 800-38A §6.4) ───────────────────────────────────────
//
// O_1 = CIPH_K(IV); O_j = CIPH_K(O_{j-1}); C_j = P_j XOR O_j. Direction-
// symmetric like CTR (XOR is its own inverse) — no CipherDirection needed.

pub struct OfbState {
    key: AesKey,
    register: [u8; BLOCK],
    keystream: [u8; BLOCK],
    ks_pos: usize,
}

impl OfbState {
    pub fn new(key: AesKey, iv: [u8; BLOCK]) -> Self {
        Self { key, register: iv, keystream: [0u8; BLOCK], ks_pos: BLOCK }
    }

    fn next_keystream_byte(&mut self) -> u8 {
        if self.ks_pos == BLOCK {
            self.key.encrypt_block(&mut self.register);
            self.keystream = self.register;
            self.ks_pos = 0;
        }
        let b = self.keystream[self.ks_pos];
        self.ks_pos += 1;
        b
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        part.iter().map(|&b| b ^ self.next_keystream_byte()).collect()
    }

    pub fn update_public(&mut self, part: &[u8]) -> Vec<u8> {
        self.update(part)
    }
}

// ── CFB-128 (§6.11, NIST SP 800-38A §6.3, segment size = block size) ───────
//
// O_j = CIPH_K(I_j); C_j = P_j XOR O_j (encrypt) / P_j = C_j XOR O_j
// (decrypt); I_{j+1} = C_j (full-block feedback, always the CIPHERTEXT
// segment regardless of direction). SP 800-38A allows a short final
// segment; a short segment never needs its own feedback since there is no
// following round, so `process_block` only shifts the register on a full
// 16-byte segment.

pub struct Cfb128State {
    key: AesKey,
    register: [u8; BLOCK],
    dir: CipherDirection,
    buf: Vec<u8>,
}

impl Cfb128State {
    pub fn new(key: AesKey, iv: [u8; BLOCK], dir: CipherDirection) -> Self {
        Self { key, register: iv, dir, buf: Vec::new() }
    }

    fn process_segment(&mut self, seg_in: &[u8]) -> Vec<u8> {
        let mut o = self.register;
        self.key.encrypt_block(&mut o);
        let out: Vec<u8> = seg_in.iter().zip(o.iter()).map(|(&b, &k)| b ^ k).collect();
        let ct_segment: &[u8] = match self.dir {
            CipherDirection::Encrypt => &out,
            CipherDirection::Decrypt => seg_in,
        };
        if ct_segment.len() == BLOCK {
            self.register.copy_from_slice(ct_segment);
        }
        out
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(part);
        let mut out = Vec::new();
        while self.buf.len() >= BLOCK {
            let block: Vec<u8> = self.buf.drain(..BLOCK).collect();
            out.extend(self.process_segment(&block));
        }
        out
    }

    /// Flush a genuinely short final segment (SP 800-38A permits this only
    /// as the last segment of the message — see `process_segment`).
    fn finalize(mut self) -> Vec<u8> {
        if self.buf.is_empty() {
            return Vec::new();
        }
        let rem = std::mem::take(&mut self.buf);
        self.process_segment(&rem)
    }

    pub fn update_public(&mut self, part: &[u8]) -> Vec<u8> {
        let mut out = self.update(part);
        if !self.buf.is_empty() {
            let rem: Vec<u8> = self.buf.drain(..).collect();
            out.extend(self.process_segment(&rem));
        }
        out
    }
}

// ── CFB-8 (§6.11, NIST SP 800-38A §6.3, segment size = 1 byte) ─────────────
//
// Byte-granular: every input byte costs one full AES block encryption.
// I_{j+1} = LSB_120(I_j) || C_j (shift the 16-byte register left one byte,
// append the ciphertext byte).

pub struct Cfb8State {
    key: AesKey,
    register: [u8; BLOCK],
    dir: CipherDirection,
}

impl Cfb8State {
    pub fn new(key: AesKey, iv: [u8; BLOCK], dir: CipherDirection) -> Self {
        Self { key, register: iv, dir }
    }

    fn step(&mut self, in_byte: u8) -> u8 {
        let mut o = self.register;
        self.key.encrypt_block(&mut o);
        let out_byte = in_byte ^ o[0];
        let ct_byte = match self.dir {
            CipherDirection::Encrypt => out_byte,
            CipherDirection::Decrypt => in_byte,
        };
        self.register.copy_within(1.., 0);
        self.register[BLOCK - 1] = ct_byte;
        out_byte
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        part.iter().map(|&b| self.step(b)).collect()
    }

    pub fn update_public(&mut self, part: &[u8]) -> Vec<u8> {
        self.update(part)
    }
}

// ── CFB-1 (§6.11, NIST SP 800-38A §6.3, segment size = 1 bit) ──────────────
//
// Bit-granular, MSB-first within each byte (matches this session's earlier
// verification of OpenSSL's EVP_aes_128_cfb1 bit ordering for the C++
// engine). I_{j+1} = the 128-bit register shifted left by 1 bit with the
// ciphertext bit inserted at the LSB.

pub struct Cfb1State {
    key: AesKey,
    register: [u8; BLOCK],
    dir: CipherDirection,
}

impl Cfb1State {
    pub fn new(key: AesKey, iv: [u8; BLOCK], dir: CipherDirection) -> Self {
        Self { key, register: iv, dir }
    }

    fn step_bit(&mut self, in_bit: u8) -> u8 {
        let mut o = self.register;
        self.key.encrypt_block(&mut o);
        let msb = (o[0] >> 7) & 1;
        let out_bit = in_bit ^ msb;
        let ct_bit = match self.dir {
            CipherDirection::Encrypt => out_bit,
            CipherDirection::Decrypt => in_bit,
        };
        let mut carry = ct_bit;
        for byte in self.register.iter_mut().rev() {
            let new_carry = (*byte >> 7) & 1;
            *byte = (*byte << 1) | carry;
            carry = new_carry;
        }
        out_bit
    }

    fn update(&mut self, part: &[u8]) -> Vec<u8> {
        part.iter()
            .map(|&byte_in| {
                let mut out_byte = 0u8;
                for i in 0..8 {
                    let bit = (byte_in >> (7 - i)) & 1;
                    let out_bit = self.step_bit(bit);
                    out_byte = (out_byte << 1) | out_bit;
                }
                out_byte
            })
            .collect()
    }

    pub fn update_public(&mut self, part: &[u8]) -> Vec<u8> {
        self.update(part)
    }
}

// ── CCM (§6.11.3, NIST SP 800-38C) ──────────────────────────────────────────
//
// Hand-rolled directly on AesKey — no existing partial implementation to
// build on (unlike GMAC/OFB/CFB) and the RustCrypto `ccm` crate's tag/nonce
// lengths are compile-time generics, which doesn't fit PKCS#11's runtime-
// variable CK_CCM_PARAMS.ulMACLen/ulNonceLen. Single-shot only (no
// multipart streaming) — SP 800-38C bakes the total plaintext length into
// the first CBC-MAC block (B_0), so the length must be known upfront, same
// as this engine's existing RSA-OAEP/ChaCha20-Poly1305 single-part-only
// mechanisms. `tag_len` in bytes (caller validates against the mechanism's
// {4,6,8,10,12,14,16} set); `nonce.len()` in 7..=13 (q = 15-nonce.len() is
// SP 800-38C's length-field width, 2..=8 bytes).

fn ccm_flags_b0(aad_present: bool, tag_len: usize, q: usize) -> u8 {
    let adata = if aad_present { 1u8 } else { 0u8 };
    (adata << 6) | ((((tag_len - 2) / 2) as u8) << 3) | ((q - 1) as u8)
}

fn ccm_encode_len(len: u64, width: usize) -> Vec<u8> {
    let full = len.to_be_bytes();
    full[8 - width..].to_vec()
}

/// B_0 (SP 800-38C Appendix A): flags || nonce || [len(payload)]_q.
fn ccm_b0(nonce: &[u8], aad_present: bool, tag_len: usize, payload_len: usize) -> [u8; BLOCK] {
    let q = 15 - nonce.len();
    let mut b0 = [0u8; BLOCK];
    b0[0] = ccm_flags_b0(aad_present, tag_len, q);
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    b0[1 + nonce.len()..BLOCK].copy_from_slice(&ccm_encode_len(payload_len as u64, q));
    b0
}

/// AAD length-prefix (2/6/10 bytes depending on magnitude) + AAD bytes,
/// zero-padded to a 16-byte boundary (SP 800-38C Appendix A).
fn ccm_aad_blocks(aad: &[u8]) -> Vec<u8> {
    if aad.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let n = aad.len() as u64;
    if n < 0xFF00 {
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        buf.push(0xFF);
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        buf.push(0xFF);
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_be_bytes());
    }
    buf.extend_from_slice(aad);
    while buf.len() % BLOCK != 0 {
        buf.push(0);
    }
    buf
}

fn ccm_zero_pad(mut data: Vec<u8>) -> Vec<u8> {
    while data.len() % BLOCK != 0 {
        data.push(0);
    }
    data
}

/// CBC-MAC over B_0 || AAD-blocks || payload-blocks: Y_1 = E(K,B_0),
/// Y_i = E(K, Y_{i-1} XOR B_i). `payload` is always the PLAINTEXT — CCM
/// authenticates plaintext on both encrypt and decrypt.
fn ccm_cbc_mac(
    key: &AesKey,
    nonce: &[u8],
    aad: &[u8],
    payload: &[u8],
    tag_len: usize,
) -> [u8; BLOCK] {
    let mut y = ccm_b0(nonce, !aad.is_empty(), tag_len, payload.len());
    key.encrypt_block(&mut y);
    let mut mac_step = |block: &[u8]| {
        let mut x = y;
        for (xi, bi) in x.iter_mut().zip(block.iter()) {
            *xi ^= bi;
        }
        key.encrypt_block(&mut x);
        y = x;
    };
    for block in ccm_aad_blocks(aad).chunks(BLOCK) {
        mac_step(block);
    }
    if !payload.is_empty() {
        for block in ccm_zero_pad(payload.to_vec()).chunks(BLOCK) {
            mac_step(block);
        }
    }
    y
}

/// Counter block i: flags(Adata=0, tag-length bits=0, just [q-1]) || nonce
/// || [i]_q. `i = 0` masks the tag (S_0); `i = 1, 2, ...` is the payload
/// keystream.
fn ccm_ctr_block(nonce: &[u8], counter: u64) -> [u8; BLOCK] {
    let q = 15 - nonce.len();
    let mut blk = [0u8; BLOCK];
    blk[0] = (q - 1) as u8;
    blk[1..1 + nonce.len()].copy_from_slice(nonce);
    blk[1 + nonce.len()..BLOCK].copy_from_slice(&ccm_encode_len(counter, q));
    blk
}

fn ccm_keystream_xor(key: &AesKey, nonce: &[u8], start_counter: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = start_counter;
    for chunk in data.chunks(BLOCK) {
        let mut ks = ccm_ctr_block(nonce, counter);
        key.encrypt_block(&mut ks);
        for (b, k) in chunk.iter().zip(ks.iter()) {
            out.push(b ^ k);
        }
        counter += 1;
    }
    out
}

/// Returns ciphertext || tag (tag_len bytes appended), matching PKCS#11
/// v3.2 §6.11.3's single-buffer CCM output convention.
pub fn ccm_encrypt(key: &AesKey, nonce: &[u8], aad: &[u8], plaintext: &[u8], tag_len: usize) -> Vec<u8> {
    let t = ccm_cbc_mac(key, nonce, aad, plaintext, tag_len);
    let mut s0 = ccm_ctr_block(nonce, 0);
    key.encrypt_block(&mut s0);
    let tag: Vec<u8> = t.iter().zip(s0.iter()).take(tag_len).map(|(a, b)| a ^ b).collect();
    let mut ct = ccm_keystream_xor(key, nonce, 1, plaintext);
    ct.extend_from_slice(&tag);
    ct
}

/// `ciphertext_and_tag` = ciphertext || tag (tag_len trailing bytes).
/// Constant-time tag comparison; unauthenticated plaintext is zeroized
/// before returning the error, matching GcmState::msg_verify_tag's
/// convention elsewhere in this module.
pub fn ccm_decrypt(
    key: &AesKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, u32> {
    if ciphertext_and_tag.len() < tag_len {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let split = ciphertext_and_tag.len() - tag_len;
    let (ct, recv_tag) = ciphertext_and_tag.split_at(split);
    let mut pt = ccm_keystream_xor(key, nonce, 1, ct);
    let t = ccm_cbc_mac(key, nonce, aad, &pt, tag_len);
    let mut s0 = ccm_ctr_block(nonce, 0);
    key.encrypt_block(&mut s0);
    let expected_tag: Vec<u8> = t.iter().zip(s0.iter()).take(tag_len).map(|(a, b)| a ^ b).collect();
    if bool::from(expected_tag.ct_eq(recv_tag)) {
        Ok(pt)
    } else {
        pt.zeroize();
        Err(CKR_ENCRYPTED_DATA_INVALID)
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
    /// Diagnostics: AES blocks generated for the payload keystream. Lets
    /// tests prove the streaming paths are single-pass (an O(n²)
    /// re-computation would inflate this quadratically).
    ks_blocks: u64,
}

/// Best-effort cleanup of streaming-state secrets. The expanded AES round
/// keys (`AesKey`) and the GHASH key inside `ghash` live in their own
/// crates' types and cannot be wiped from here; everything this struct
/// owns directly — keystream bytes, counter, E_K(J0), buffered
/// ciphertext/plaintext residue — is zeroized.
impl Drop for GcmState {
    fn drop(&mut self) {
        self.keystream.zeroize();
        self.counter.zeroize();
        self.ek_j0.zeroize();
        self.ghash_buf.zeroize();
        self.pending.zeroize();
    }
}

impl GcmState {
    /// `iv` is the GCM IV — any length in SP 800-38D's 1..2^64-bit range
    /// (callers validate non-empty); 96-bit IVs take the fast J0 path,
    /// every other length derives J0 through GHASH (§7.1 step 2b).
    /// `tag_bits` of 0 defaults to a full 128-bit tag.
    pub fn new(
        key: AesKey,
        iv: &[u8],
        aad: &[u8],
        tag_bits: u32,
        dir: CipherDirection,
    ) -> Self {
        // H = E_K(0^128) keys GHASH (SP 800-38D §7.1 step 1).
        let mut h = [0u8; BLOCK];
        key.encrypt_block(&mut h);
        let mut ghash = GHash::new(GenericArray::from_slice(&h));
        ghash.update_padded(aad);

        // §7.1 step 2: J0 = IV || 0^31 || 1 when len(IV) = 96 bits;
        // otherwise J0 = GHASH_H(IV || 0-pad || 0^64 || [len(IV)]_64).
        let mut j0 = [0u8; BLOCK];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
        } else {
            let mut g = GHash::new(GenericArray::from_slice(&h));
            g.update_padded(iv);
            let mut len_block = [0u8; BLOCK];
            len_block[8..].copy_from_slice(&((iv.len() as u64) * 8).to_be_bytes());
            g.update(&[len_block.into()]);
            j0.copy_from_slice(&g.finalize());
        }
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
            ks_blocks: 0,
        }
    }

    /// Payload keystream blocks generated so far (see `ks_blocks`).
    pub fn keystream_blocks(&self) -> u64 {
        self.ks_blocks
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
            self.ks_blocks += 1;
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

    /// PKCS#11 v3.2 §5.15 message-based streaming
    /// (`C_EncryptMessageBegin/Next`, `C_DecryptMessageBegin/Next`): unlike
    /// the §5.2 multipart convention, the authentication tag travels
    /// out-of-band in `CK_GCM_MESSAGE_PARAMS.pTag`, so every input byte is
    /// payload — decrypt has NO tag hold-back. Both directions are O(chunk):
    /// the partial CTR keystream block (`keystream`/`ks_pos`) carries across
    /// chunk boundaries that don't align to 16 bytes, and the running GHASH
    /// absorbs the ciphertext incrementally via `ghash_buf`.
    pub fn msg_update(&mut self, part: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(part.len());
        match self.dir {
            CipherDirection::Encrypt => {
                for &pt in part {
                    let ct = pt ^ self.next_keystream_byte();
                    self.ghash_feed(ct);
                    out.push(ct);
                }
            }
            CipherDirection::Decrypt => {
                for &ct in part {
                    self.ghash_feed(ct);
                    out.push(ct ^ self.next_keystream_byte());
                }
            }
        }
        self.ct_len += part.len() as u64;
        out
    }

    /// Message-API encrypt finalization: the SP 800-38D §7.1 tag (lengths
    /// block, final GHASH, E_K(J0) XOR), truncated to the `tag_bits`
    /// requested at construction. Consumes the operation.
    pub fn msg_compute_tag(self) -> Vec<u8> {
        self.compute_tag()
    }

    /// Message-API decrypt finalization: verify the externally-supplied
    /// (possibly truncated) tag in constant time. Consumes the operation;
    /// `Err(CKR_ENCRYPTED_DATA_INVALID)` on mismatch.
    pub fn msg_verify_tag(self, tag: &[u8]) -> Result<(), u32> {
        let expected = self.compute_tag();
        if !tag.is_empty()
            && tag.len() <= expected.len()
            && bool::from(expected[..tag.len()].ct_eq(tag))
        {
            Ok(())
        } else {
            Err(CKR_ENCRYPTED_DATA_INVALID)
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
        // Clone before the consuming `finalize` — `GcmState` has a `Drop`
        // impl, so fields cannot be moved out of `self`.
        let s = self.ghash.clone().finalize();
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

    // Same set, test case 5: 8-byte (64-bit) IV — exercises the GHASH
    // J0 derivation of SP 800-38D §7.1 step 2b. Also pinned on the wire
    // by OASIS KMIP CS-BC-M-GCM-3.
    #[test]
    fn gcm_kat_64_bit_iv() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbad");
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let ct = hex(
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
             73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        );
        let tag = hex("3612d2e79e3b0785561be14aaca2fccb");
        run_gcm_kat(&key, &iv, &aad, &pt, &ct, &tag);
    }

    fn run_gcm_kat(key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8], ct: &[u8], tag: &[u8]) {
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

    // ── Message-API streaming (msg_update / msg_compute_tag / msg_verify_tag) ──

    /// Split `data` into parts of `sizes` (cycled; 0 produces an explicit
    /// empty part).
    fn split<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut off = 0;
        let mut i = 0;
        while off < data.len() {
            let n = sizes[i % sizes.len()].min(data.len() - off);
            parts.push(&data[off..off + n]);
            off += n;
            i += 1;
        }
        if parts.is_empty() {
            parts.push(&data[..0]);
        }
        parts
    }

    const MSG_CHUNKINGS: &[&[usize]] = &[&[1], &[16], &[7, 13], &[5, 0, 9], &[64]];

    /// Message-API streaming must reproduce the SP 800-38D KATs for every
    /// chunking (1-byte, block-aligned, odd 7/13, with empty parts) and for
    /// truncated 96-bit tags — chunked ciphertext concatenation must
    /// byte-match the one-shot answer.
    #[test]
    fn gcm_msg_streaming_matches_kats() {
        // McGrew–Viega TC3 (no AAD), TC4 (AAD), TC5 (64-bit IV → §7.1
        // step-2b J0 derivation) — same vectors as the §5.2 KATs above.
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let pt_full = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let cases: &[(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)] = &[
            (
                hex("cafebabefacedbaddecaf888"),
                Vec::new(),
                pt_full.clone(),
                hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                ),
                hex("4d5c2af327cd64a62cf35abd2ba6fab4"),
            ),
            (
                hex("cafebabefacedbaddecaf888"),
                aad.clone(),
                pt_full[..60].to_vec(),
                hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                ),
                hex("5bc94fbc3221a5db94fae95ae7121a47"),
            ),
            (
                hex("cafebabefacedbad"),
                aad.clone(),
                pt_full[..60].to_vec(),
                hex(
                    "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423\
                     73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
                ),
                hex("3612d2e79e3b0785561be14aaca2fccb"),
            ),
        ];
        for (iv, aad, pt, ct, tag) in cases {
            for sizes in MSG_CHUNKINGS {
                for tag_bytes in [16usize, 12] {
                    // Encrypt: concatenated chunks == one-shot ciphertext.
                    let mut enc = GcmState::new(
                        AesKey::new(&key).unwrap(),
                        iv,
                        aad,
                        128,
                        CipherDirection::Encrypt,
                    );
                    let mut got_ct = Vec::new();
                    for part in split(pt, sizes) {
                        got_ct.extend_from_slice(&enc.msg_update(part));
                    }
                    let got_tag = enc.msg_compute_tag();
                    assert_eq!(&got_ct, ct, "sizes={sizes:?}");
                    assert_eq!(&got_tag[..tag_bytes], &tag[..tag_bytes], "sizes={sizes:?}");

                    // Decrypt round-trip with the (possibly truncated) tag.
                    let mut dec = GcmState::new(
                        AesKey::new(&key).unwrap(),
                        iv,
                        aad,
                        128,
                        CipherDirection::Decrypt,
                    );
                    let mut got_pt = Vec::new();
                    for part in split(ct, sizes) {
                        got_pt.extend_from_slice(&dec.msg_update(part));
                    }
                    assert_eq!(&got_pt, pt, "sizes={sizes:?}");
                    dec.msg_verify_tag(&tag[..tag_bytes]).unwrap();
                }
            }
        }
    }

    #[test]
    fn gcm_msg_verify_rejects_tampered_or_empty_tag() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let pt = b"attack at dawn";
        let mut enc =
            GcmState::new(AesKey::new(&key).unwrap(), &iv, &[], 128, CipherDirection::Encrypt);
        let ct = enc.msg_update(pt);
        let tag = enc.msg_compute_tag();

        let mut dec =
            GcmState::new(AesKey::new(&key).unwrap(), &iv, &[], 128, CipherDirection::Decrypt);
        dec.msg_update(&ct);
        let mut bad = tag.clone();
        bad[0] ^= 1;
        assert_eq!(dec.msg_verify_tag(&bad).unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);

        let mut dec =
            GcmState::new(AesKey::new(&key).unwrap(), &iv, &[], 128, CipherDirection::Decrypt);
        dec.msg_update(&ct);
        assert_eq!(dec.msg_verify_tag(&[]).unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);
    }

    /// O(n) proof: streaming 512 × 64-byte parts must generate exactly
    /// 32768/16 = 2048 payload keystream blocks — a quadratic re-run of the
    /// accumulated payload (the pre-T5 ffi behavior) would generate ~525k.
    /// Also checks the partial-block carry: misaligned 7-byte chunks must
    /// not waste keystream.
    #[test]
    fn gcm_msg_streaming_is_single_pass() {
        let mut g = GcmState::new(
            AesKey::new(&[0x42u8; 16]).unwrap(),
            &[9u8; 12],
            b"aad",
            128,
            CipherDirection::Encrypt,
        );
        let part = [0xA5u8; 64];
        for _ in 0..512 {
            g.msg_update(&part);
        }
        assert_eq!(g.keystream_blocks(), 2048);
        let _ = g.msg_compute_tag();

        let mut g = GcmState::new(
            AesKey::new(&[0x42u8; 16]).unwrap(),
            &[9u8; 12],
            &[],
            128,
            CipherDirection::Decrypt,
        );
        for _ in 0..10 {
            g.msg_update(&[0u8; 7]); // 70 bytes total
        }
        assert_eq!(g.keystream_blocks(), 5); // ceil(70/16)
    }
}
