//! Packed layouts and constants of the hash-signature engine ABI v1.
//!
//! Source of truth: `pqctoday-cacp` `fpga/hashsig/hashsig_abi.hpp` (the header
//! wins over `ABI.md` where they disagree). Every constant below is copied
//! from that header; the unit tests at the bottom pin the record sizes and
//! payload sizes it `static_assert`s.

use std::fmt;

// ---------------------------------------------------------------------------
// Transport constants
// ---------------------------------------------------------------------------
pub const REQUEST_MAGIC: u32 = 0x3152_5348; // "HSR1" little-endian
pub const COMPLETION_MAGIC: u32 = 0x3143_5348; // "HSC1" little-endian
pub const ABI_VERSION: u16 = 1;
pub const REQUEST_BYTES: usize = 64;
pub const COMPLETION_BYTES: usize = 64;
pub const DMA_ALIGNMENT: usize = 64;
/// One request never needs more than this many bytes of the DMA buffer.
pub const DMA_MIN_BYTES: usize = 32_768;
/// Request-table records per start (ABI.md §4.1).
pub const MAX_BATCH: u32 = 16;
/// Upper bound on DMA_BYTES.
pub const DMA_MAX_BYTES: u64 = 0x4000_0000;

// AXI4-Lite register map (Vitis HLS 2026.1, `hashsig_engine(dma, dma_bytes)`).
pub const REG_AP_CTRL: usize = 0x00;
pub const REG_GIE: usize = 0x04;
pub const REG_IER: usize = 0x08;
pub const REG_ISR: usize = 0x0c;
pub const REG_RETURN: usize = 0x10;
pub const REG_DMA_LO: usize = 0x18;
pub const REG_DMA_HI: usize = 0x1c;
pub const REG_DMA_BYTES: usize = 0x24;
pub const AP_START: u32 = 1 << 0;
pub const AP_DONE: u32 = 1 << 1;
pub const AP_IDLE: u32 = 1 << 2;
pub const AP_READY: u32 = 1 << 3;
pub const AP_AUTO_RESTART: u32 = 1 << 7;

// Physical map (PS M_AXI_HPM0_FPD).
pub const UIO_ENGINE0_BASE: u64 = 0xA010_0000;
/// Reserved by the ABI, not built in v1. The driver never probes it.
pub const UIO_ENGINE1_BASE: u64 = 0xA011_0000;
pub const UIO_WINDOW_BYTES: usize = 0x1_0000;
/// The behaviour TCN window, identical in every profile. Never touched here.
pub const UIO_TCN_BASE: u64 = 0xA006_0000;

/// `auth_leaf` value meaning "no authentication path".
pub const AUTH_LEAF_NONE: u32 = 0xffff_ffff;

pub const SLH_SIGN_INPUT_BYTES: usize = 160;
pub const SLH_KEYGEN_INPUT_BYTES: usize = 64;
pub const MERKLE_INPUT_BYTES: usize = 128;
pub const CAPS_BYTES: usize = 128;

pub const SCHEME_LMS: u32 = 0x01;
pub const SCHEME_XMSS: u32 = 0x02;

// ---------------------------------------------------------------------------
// Commands and status
// ---------------------------------------------------------------------------

/// Command opcodes (counter-map-v2 slots). Opcode 19 (`slh_verify`) stays
/// reserved: verification is ARM-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Command {
    SlhSign = 20,
    Scrub = 22,
    SlhKeygen = 23,
    MerkleSubtree = 24,
    QueryCaps = 25,
    ResetCore = 26,
}

impl Command {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            20 => Self::SlhSign,
            22 => Self::Scrub,
            23 => Self::SlhKeygen,
            24 => Self::MerkleSubtree,
            25 => Self::QueryCaps,
            26 => Self::ResetCore,
            _ => return None,
        })
    }

    /// The exact `input_length` the engine requires.
    pub fn input_len(self) -> usize {
        match self {
            Self::SlhSign => SLH_SIGN_INPUT_BYTES,
            Self::SlhKeygen => SLH_KEYGEN_INPUT_BYTES,
            Self::MerkleSubtree => MERKLE_INPUT_BYTES,
            Self::QueryCaps | Self::Scrub | Self::ResetCore => 0,
        }
    }

    /// Commands that carry a parameter set; the others require `param_set == 0`.
    pub fn takes_param_set(self) -> bool {
        matches!(self, Self::SlhSign | Self::SlhKeygen | Self::MerkleSubtree)
    }
}

/// `Completion.status` / `RETURN` values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    BadDescriptor = -1,
    UnsupportedCommand = -2,
    UnsupportedParameterSet = -3,
    InvalidInput = -4,
    RootMismatch = -5,
    InternalError = -6,
    ScrubFailure = -7,
}

impl Status {
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Success,
            -1 => Self::BadDescriptor,
            -2 => Self::UnsupportedCommand,
            -3 => Self::UnsupportedParameterSet,
            -4 => Self::InvalidInput,
            -5 => Self::RootMismatch,
            -6 => Self::InternalError,
            -7 => Self::ScrubFailure,
            _ => return None,
        })
    }

    /// counter-map-v2 fallback reason the engine reports with this status.
    pub fn fallback_reason(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::BadDescriptor | Self::InvalidInput => 11,
            Self::UnsupportedCommand => 9,
            Self::UnsupportedParameterSet => 10,
            Self::RootMismatch => 14,
            Self::InternalError => 15,
            Self::ScrubFailure => 6,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}({})", *self as i32)
    }
}

// ---------------------------------------------------------------------------
// Parameter sets
// ---------------------------------------------------------------------------

/// Hash family of a parameter set. The routing policy is expressed per family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HashFamily {
    /// SHA-256 / SHA-512 (SLH-DSA SHA2, LMS SHA-256, XMSS SHA2).
    Sha2,
    /// SHAKE128 / SHAKE256 (SLH-DSA SHAKE, LMS SHAKE256, XMSS SHAKE*).
    Shake,
}

/// One row of FIPS 205 Table 2; `id` is the row number (ABI.md §7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlhParam {
    pub id: u32,
    pub name: &'static str,
    pub n: usize,
    pub h: usize,
    pub d: usize,
    pub hp: usize,
    pub a: usize,
    pub k: usize,
    pub len: usize,
    pub family: HashFamily,
    /// The **s** sets are the only ones v1 can claim (owner decision P2).
    pub small: bool,
}

impl SlhParam {
    /// ⌈k·a/8⌉: bytes of the H_msg digest that form `md`.
    pub fn md_bytes(&self) -> usize {
        (self.k * self.a).div_ceil(8)
    }
    /// SIG_FORS ‖ SIG_HT = signature minus R.
    pub fn payload_bytes(&self) -> usize {
        (self.k * (1 + self.a) + self.h + self.d * self.len) * self.n
    }
    pub fn signature_bytes(&self) -> usize {
        self.n + self.payload_bytes()
    }
    /// Bits of `idx_tree`: h − h'.
    pub fn idx_tree_bits(&self) -> usize {
        self.h - self.hp
    }
}

#[allow(clippy::too_many_arguments)]
const fn slh(
    id: u32,
    name: &'static str,
    n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    family: HashFamily,
    small: bool,
) -> SlhParam {
    SlhParam {
        id,
        name,
        n,
        h,
        d,
        hp,
        a,
        k,
        len: 2 * n + 3,
        family,
        small,
    }
}

use HashFamily::{Sha2, Shake};
pub const SLH_PARAMS: [SlhParam; 12] = [
    slh(1, "SLH-DSA-SHA2-128s", 16, 63, 7, 9, 12, 14, Sha2, true),
    slh(2, "SLH-DSA-SHAKE-128s", 16, 63, 7, 9, 12, 14, Shake, true),
    slh(3, "SLH-DSA-SHA2-128f", 16, 66, 22, 3, 6, 33, Sha2, false),
    slh(4, "SLH-DSA-SHAKE-128f", 16, 66, 22, 3, 6, 33, Shake, false),
    slh(5, "SLH-DSA-SHA2-192s", 24, 63, 7, 9, 14, 17, Sha2, true),
    slh(6, "SLH-DSA-SHAKE-192s", 24, 63, 7, 9, 14, 17, Shake, true),
    slh(7, "SLH-DSA-SHA2-192f", 24, 66, 22, 3, 8, 33, Sha2, false),
    slh(8, "SLH-DSA-SHAKE-192f", 24, 66, 22, 3, 8, 33, Shake, false),
    slh(9, "SLH-DSA-SHA2-256s", 32, 64, 8, 8, 14, 22, Sha2, true),
    slh(10, "SLH-DSA-SHAKE-256s", 32, 64, 8, 8, 14, 22, Shake, true),
    slh(11, "SLH-DSA-SHA2-256f", 32, 68, 17, 4, 9, 35, Sha2, false),
    slh(12, "SLH-DSA-SHAKE-256f", 32, 68, 17, 4, 9, 35, Shake, false),
];

pub fn slh_param(id: u32) -> Option<&'static SlhParam> {
    SLH_PARAMS.iter().find(|p| p.id == id)
}

/// LMS/LM-OTS pair decoded from a MERKLE_SUBTREE `param_set` (ABI.md §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LmsParam {
    pub lms_type: u32,
    pub lmots_type: u32,
    /// `Caps.lms_families` bit: 0 SHA-256/M32, 1 SHA-256/M24, 2 SHAKE256/M32, 3 SHAKE256/M24.
    pub family_bit: u32,
    /// `Caps.lmots_w` bit: 0 W1, 1 W2, 2 W4, 3 W8.
    pub w_bit: u32,
    pub n: usize,
    pub height: u32,
    pub w: u32,
    pub family: HashFamily,
}

impl LmsParam {
    /// LM-OTS chain count p (RFC 8554 Appendix B, SP 800-208 Table 3/4).
    pub fn chains(&self) -> u64 {
        let u = (8 * self.n as u64).div_ceil(u64::from(self.w));
        let max = ((1u64 << self.w) - 1) * u;
        let v = (u64::from(max.ilog2()) + 1).div_ceil(u64::from(self.w));
        u + v
    }
}

pub fn lms_param_set(lms_type: u32, lmots_type: u32) -> u32 {
    (SCHEME_LMS << 24) | ((lms_type & 0xff) << 8) | (lmots_type & 0xff)
}

pub fn lms_param(param_set: u32) -> Option<LmsParam> {
    if param_set >> 24 != SCHEME_LMS || (param_set >> 16) & 0xff != 0 {
        return None;
    }
    let lms_type = (param_set >> 8) & 0xff;
    let lmots_type = param_set & 0xff;
    let (family_bit, h_off) = match lms_type {
        0x05..=0x09 => (0, lms_type - 0x05),
        0x0A..=0x0E => (1, lms_type - 0x0A),
        0x0F..=0x13 => (2, lms_type - 0x0F),
        0x14..=0x18 => (3, lms_type - 0x14),
        _ => return None,
    };
    let (ots_family, w_off) = match lmots_type {
        0x01..=0x04 => (0, lmots_type - 0x01),
        0x05..=0x08 => (1, lmots_type - 0x05),
        0x09..=0x0C => (2, lmots_type - 0x09),
        0x0D..=0x10 => (3, lmots_type - 0x0D),
        _ => return None,
    };
    if ots_family != family_bit {
        return None;
    }
    Some(LmsParam {
        lms_type,
        lmots_type,
        family_bit,
        w_bit: w_off,
        n: if family_bit % 2 == 0 { 32 } else { 24 },
        height: [5, 10, 15, 20, 25][h_off as usize],
        w: [1, 2, 4, 8][w_off as usize],
        family: if family_bit < 2 { Sha2 } else { Shake },
    })
}

/// XMSS / XMSS^MT parameter set decoded from a MERKLE_SUBTREE `param_set`
/// (ABI.md §7.3). The table mirrors `xmss 0.1.0-pre.0` `XmssOid::initialize`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmssParam {
    /// The xmss crate's encoding: `0x0000_00XX` XMSS, `0x0001_00XX` XMSS^MT.
    pub raw_oid: u32,
    /// `Caps.xmss_families` bit: 0 SHA2 n32, 1 SHA2 n24, 2 SHAKE128 n32,
    /// 3 SHAKE256 n32, 4 SHAKE256 n24, 5 SHA2 n64, 6 SHAKE256 n64.
    pub family_bit: u32,
    pub n: usize,
    pub full_height: u32,
    pub d: u32,
    pub family: HashFamily,
}

impl XmssParam {
    /// Height of one tree: h/d.
    pub fn tree_height(&self) -> u32 {
        self.full_height / self.d
    }
    /// WOTS+ chains, w = 16.
    pub fn wots_len(&self) -> u64 {
        2 * self.n as u64 + 3
    }
}

pub fn xmss_param_set(raw_oid: u32) -> u32 {
    (SCHEME_XMSS << 24) | (raw_oid & 0x00ff_ffff)
}

pub fn xmss_param(param_set: u32) -> Option<XmssParam> {
    if param_set >> 24 != SCHEME_XMSS {
        return None;
    }
    let raw_oid = param_set & 0x00ff_ffff;
    let raw = raw_oid & 0xffff;
    match raw_oid >> 16 {
        0 => {
            // (family bit, n)
            let (family_bit, n) = match raw {
                0x01..=0x03 => (0, 32),
                0x04..=0x06 => (5, 64),
                0x07..=0x09 => (2, 32),
                0x0a..=0x0c => (6, 64),
                0x0d..=0x0f => (1, 24),
                0x10..=0x12 => (3, 32),
                0x13..=0x15 => (4, 24),
                _ => return None,
            };
            let full_height = [10, 16, 20][((raw - 1) % 3) as usize];
            Some(XmssParam {
                raw_oid,
                family_bit,
                n,
                full_height,
                d: 1,
                family: xmss_family(family_bit),
            })
        }
        1 => {
            let (family_bit, n) = match raw {
                0x01..=0x08 => (0, 32),
                0x09..=0x10 => (5, 64),
                0x11..=0x18 => (2, 32),
                0x19..=0x20 => (6, 64),
                0x21..=0x28 => (1, 24),
                0x29..=0x30 => (3, 32),
                0x31..=0x38 => (4, 24),
                _ => return None,
            };
            // Every block of eight uses the same (h, d) order.
            let (full_height, d) = [
                (20, 2),
                (20, 4),
                (40, 2),
                (40, 4),
                (40, 8),
                (60, 3),
                (60, 6),
                (60, 12),
            ][((raw - 1) % 8) as usize];
            Some(XmssParam {
                raw_oid,
                family_bit,
                n,
                full_height,
                d,
                family: xmss_family(family_bit),
            })
        }
        _ => None,
    }
}

fn xmss_family(bit: u32) -> HashFamily {
    match bit {
        0 | 1 | 5 => Sha2,
        _ => Shake,
    }
}

/// Parameter set of any command, decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamSet {
    Slh(&'static SlhParam),
    Lms(LmsParam),
    Xmss(XmssParam),
}

impl ParamSet {
    pub fn decode(command: Command, param_set: u32) -> Option<Self> {
        match command {
            Command::SlhSign | Command::SlhKeygen => slh_param(param_set).map(Self::Slh),
            Command::MerkleSubtree => lms_param(param_set)
                .map(Self::Lms)
                .or_else(|| xmss_param(param_set).map(Self::Xmss)),
            _ => None,
        }
    }

    pub fn n(&self) -> usize {
        match self {
            Self::Slh(p) => p.n,
            Self::Lms(p) => p.n,
            Self::Xmss(p) => p.n,
        }
    }

    pub fn family(&self) -> HashFamily {
        match self {
            Self::Slh(p) => p.family,
            Self::Lms(p) => p.family,
            Self::Xmss(p) => p.family,
        }
    }

    /// MERKLE_SUBTREE tree height H (LMS height, or XMSS h/d).
    pub fn merkle_height(&self) -> Option<u32> {
        match self {
            Self::Lms(p) => Some(p.height),
            Self::Xmss(p) => Some(p.tree_height()),
            Self::Slh(_) => None,
        }
    }
}

/// Payload bytes a successful command writes after its completion record.
pub fn payload_bytes(command: Command, param: Option<&ParamSet>, subtree_height: u32) -> usize {
    match (command, param) {
        (Command::QueryCaps, _) => CAPS_BYTES,
        (Command::Scrub | Command::ResetCore, _) => 0,
        (Command::SlhSign, Some(ParamSet::Slh(p))) => p.payload_bytes(),
        (Command::SlhKeygen, Some(ParamSet::Slh(p))) => p.n,
        (Command::MerkleSubtree, Some(p)) => p.n() * (subtree_height as usize + 1),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// Request record (ABI.md §4), 64 bytes at DMA offset 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Request {
    pub magic: u32,
    pub abi_version: u16,
    pub header_bytes: u16,
    pub total_bytes: u32,
    pub command: u32,
    pub flags: u32,
    pub param_set: u32,
    pub request_id: u64,
    pub input_offset: u32,
    pub input_length: u32,
    pub output_offset: u32,
    pub output_length: u32,
    pub tenant_tag: u32,
    pub reserved: [u32; 3],
}

impl Request {
    pub fn encode(&self, out: &mut [u8]) {
        let out = &mut out[..REQUEST_BYTES];
        put_u32(out, 0, self.magic);
        put_u16(out, 4, self.abi_version);
        put_u16(out, 6, self.header_bytes);
        put_u32(out, 8, self.total_bytes);
        put_u32(out, 12, self.command);
        put_u32(out, 16, self.flags);
        put_u32(out, 20, self.param_set);
        put_u64(out, 24, self.request_id);
        put_u32(out, 32, self.input_offset);
        put_u32(out, 36, self.input_length);
        put_u32(out, 40, self.output_offset);
        put_u32(out, 44, self.output_length);
        put_u32(out, 48, self.tenant_tag);
        for (index, word) in self.reserved.iter().enumerate() {
            put_u32(out, 52 + 4 * index, *word);
        }
    }

    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            magic: get_u32(bytes, 0),
            abi_version: get_u16(bytes, 4),
            header_bytes: get_u16(bytes, 6),
            total_bytes: get_u32(bytes, 8),
            command: get_u32(bytes, 12),
            flags: get_u32(bytes, 16),
            param_set: get_u32(bytes, 20),
            request_id: get_u64(bytes, 24),
            input_offset: get_u32(bytes, 32),
            input_length: get_u32(bytes, 36),
            output_offset: get_u32(bytes, 40),
            output_length: get_u32(bytes, 44),
            tenant_tag: get_u32(bytes, 48),
            reserved: [get_u32(bytes, 52), get_u32(bytes, 56), get_u32(bytes, 60)],
        }
    }
}

/// Completion record (ABI.md §5), 64 bytes at `output_offset`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Completion {
    pub magic: u32,
    pub abi_version: u16,
    pub record_bytes: u16,
    pub status: i32,
    pub fallback_reason: u32,
    pub request_id: u64,
    pub command: u32,
    pub param_set: u32,
    pub output_bytes: u32,
    pub tenant_tag: u32,
    pub total_cycles: u64,
    pub hash_steps: u64,
    pub lanes: u32,
    pub reserved: u32,
}

impl Completion {
    pub fn encode(&self, out: &mut [u8]) {
        let out = &mut out[..COMPLETION_BYTES];
        put_u32(out, 0, self.magic);
        put_u16(out, 4, self.abi_version);
        put_u16(out, 6, self.record_bytes);
        put_u32(out, 8, self.status as u32);
        put_u32(out, 12, self.fallback_reason);
        put_u64(out, 16, self.request_id);
        put_u32(out, 24, self.command);
        put_u32(out, 28, self.param_set);
        put_u32(out, 32, self.output_bytes);
        put_u32(out, 36, self.tenant_tag);
        put_u64(out, 40, self.total_cycles);
        put_u64(out, 48, self.hash_steps);
        put_u32(out, 56, self.lanes);
        put_u32(out, 60, self.reserved);
    }

    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            magic: get_u32(bytes, 0),
            abi_version: get_u16(bytes, 4),
            record_bytes: get_u16(bytes, 6),
            status: get_u32(bytes, 8) as i32,
            fallback_reason: get_u32(bytes, 12),
            request_id: get_u64(bytes, 16),
            command: get_u32(bytes, 24),
            param_set: get_u32(bytes, 28),
            output_bytes: get_u32(bytes, 32),
            tenant_tag: get_u32(bytes, 36),
            total_cycles: get_u64(bytes, 40),
            hash_steps: get_u64(bytes, 48),
            lanes: get_u32(bytes, 56),
            reserved: get_u32(bytes, 60),
        }
    }
}

/// QUERY_CAPS payload (ABI.md §6.4), 128 bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Caps {
    pub caps_version: u32,
    pub lanes: u32,
    pub hash_cores: u32,
    pub clock_hz: u32,
    pub commands: u32,
    pub slh_sign_sets: u32,
    pub slh_keygen_sets: u32,
    pub lms_families: u32,
    pub lmots_w: u32,
    pub lms_max_subtree_height: u32,
    pub xmss_families: u32,
    pub xmss_max_subtree_height: u32,
    pub commands_completed: u64,
    pub commands_failed: u64,
    pub zeroizations: u64,
    pub build_id: u32,
    pub max_batch: u32,
    pub sha256_cores: u32,
    pub sha512_cores: u32,
    pub keccak_rounds_per_clock: u32,
    pub generic_lanes: u32,
}

pub const HASH_CORE_KECCAK: u32 = 1 << 0;
pub const HASH_CORE_SHA256: u32 = 1 << 1;
pub const HASH_CORE_SHA512: u32 = 1 << 2;

impl Caps {
    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            caps_version: get_u32(bytes, 0),
            lanes: get_u32(bytes, 4),
            hash_cores: get_u32(bytes, 8),
            clock_hz: get_u32(bytes, 12),
            commands: get_u32(bytes, 16),
            slh_sign_sets: get_u32(bytes, 20),
            slh_keygen_sets: get_u32(bytes, 24),
            lms_families: get_u32(bytes, 28),
            lmots_w: get_u32(bytes, 32),
            lms_max_subtree_height: get_u32(bytes, 36),
            xmss_families: get_u32(bytes, 40),
            xmss_max_subtree_height: get_u32(bytes, 44),
            commands_completed: get_u64(bytes, 48),
            commands_failed: get_u64(bytes, 56),
            zeroizations: get_u64(bytes, 64),
            build_id: get_u32(bytes, 72),
            max_batch: get_u32(bytes, 76),
            sha256_cores: get_u32(bytes, 80),
            sha512_cores: get_u32(bytes, 84),
            keccak_rounds_per_clock: get_u32(bytes, 88),
            generic_lanes: get_u32(bytes, 92),
        }
    }

    pub fn encode(&self, out: &mut [u8]) {
        let out = &mut out[..CAPS_BYTES];
        out.fill(0);
        put_u32(out, 0, self.caps_version);
        put_u32(out, 4, self.lanes);
        put_u32(out, 8, self.hash_cores);
        put_u32(out, 12, self.clock_hz);
        put_u32(out, 16, self.commands);
        put_u32(out, 20, self.slh_sign_sets);
        put_u32(out, 24, self.slh_keygen_sets);
        put_u32(out, 28, self.lms_families);
        put_u32(out, 32, self.lmots_w);
        put_u32(out, 36, self.lms_max_subtree_height);
        put_u32(out, 40, self.xmss_families);
        put_u32(out, 44, self.xmss_max_subtree_height);
        put_u64(out, 48, self.commands_completed);
        put_u64(out, 56, self.commands_failed);
        put_u64(out, 64, self.zeroizations);
        put_u32(out, 72, self.build_id);
        put_u32(out, 76, self.max_batch);
        put_u32(out, 80, self.sha256_cores);
        put_u32(out, 84, self.sha512_cores);
        put_u32(out, 88, self.keccak_rounds_per_clock);
        put_u32(out, 92, self.generic_lanes);
    }

    pub fn implements(&self, command: Command) -> bool {
        self.commands & (1u32 << command as u32) != 0
    }

    /// True when the engine claims `(command, param_set)` for a subtree of
    /// height `subtree_height` (ignored for SLH-DSA). Anything else runs on ARM.
    pub fn claims(&self, command: Command, param_set: u32, subtree_height: u32) -> bool {
        if !self.implements(command) {
            return false;
        }
        match ParamSet::decode(command, param_set) {
            Some(ParamSet::Slh(p)) => {
                let sets = if command == Command::SlhSign {
                    self.slh_sign_sets
                } else {
                    self.slh_keygen_sets
                };
                // Only rows 1..=12 exist; a bit is honoured only for an s set,
                // which is all v1 may claim (ABI.md §7.1).
                p.small && sets & (1u32 << p.id) != 0
            }
            Some(ParamSet::Lms(p)) => {
                self.lms_families & (1 << p.family_bit) != 0
                    && self.lmots_w & (1 << p.w_bit) != 0
                    && subtree_height <= self.lms_max_subtree_height
                    && subtree_height <= p.height
            }
            Some(ParamSet::Xmss(p)) => {
                // The n = 64 OIDs are defined but never claimed in v1.
                p.n != 64
                    && self.xmss_families & (1 << p.family_bit) != 0
                    && subtree_height <= self.xmss_max_subtree_height
                    && subtree_height <= p.tree_height()
            }
            None => false,
        }
    }

    /// Hash lanes a parameter set runs on: SHAKE uses `lanes`, SHA-2 `generic_lanes`.
    pub fn lanes_for(&self, family: HashFamily) -> u32 {
        match family {
            Shake => self.lanes.max(1),
            Sha2 => self.generic_lanes.max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Command inputs
// ---------------------------------------------------------------------------

/// SLH_SIGN input (ABI.md §6.1). `sk_seed` is secret.
#[derive(Clone, Copy, Debug)]
pub struct SlhSignInput<'a> {
    pub sk_seed: &'a [u8],
    pub pk_seed: &'a [u8],
    pub pk_root: &'a [u8],
    /// First ⌈k·a/8⌉ bytes of the H_msg digest.
    pub md: &'a [u8],
    pub idx_tree: u64,
    pub idx_leaf: u32,
}

/// SLH_KEYGEN input (ABI.md §6.2). `sk_seed` is secret.
#[derive(Clone, Copy, Debug)]
pub struct SlhKeygenInput<'a> {
    pub sk_seed: &'a [u8],
    pub pk_seed: &'a [u8],
}

/// MERKLE_SUBTREE input (ABI.md §6.3). `seed` is secret.
#[derive(Clone, Copy, Debug)]
pub struct MerkleInput<'a> {
    /// LMS: the tree's SEED; XMSS: SK_SEED.
    pub seed: &'a [u8],
    /// LMS: I (16 bytes); XMSS: PUB_SEED.
    pub public: &'a [u8],
    pub subtree_height: u32,
    pub leaf_start: u32,
    /// A leaf in the subtree, or [`AUTH_LEAF_NONE`].
    pub auth_leaf: u32,
    pub layer: u32,
    pub tree_address: u64,
}

/// A validated command ready to be written to the DMA buffer.
#[derive(Clone, Copy, Debug)]
pub enum Operation<'a> {
    SlhSign { param: u32, input: SlhSignInput<'a> },
    SlhKeygen { param: u32, input: SlhKeygenInput<'a> },
    Merkle { param: u32, input: MerkleInput<'a> },
    QueryCaps,
    Scrub,
    ResetCore,
}

/// Input encoding failures. These are driver-side checks: an operation that
/// fails them is never submitted to the engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    UnknownParameterSet,
    FieldLength,
    IndexRange,
}

impl<'a> Operation<'a> {
    pub fn command(&self) -> Command {
        match self {
            Self::SlhSign { .. } => Command::SlhSign,
            Self::SlhKeygen { .. } => Command::SlhKeygen,
            Self::Merkle { .. } => Command::MerkleSubtree,
            Self::QueryCaps => Command::QueryCaps,
            Self::Scrub => Command::Scrub,
            Self::ResetCore => Command::ResetCore,
        }
    }

    pub fn param_set(&self) -> u32 {
        match self {
            Self::SlhSign { param, .. } | Self::SlhKeygen { param, .. } | Self::Merkle { param, .. } => {
                *param
            }
            _ => 0,
        }
    }

    pub fn subtree_height(&self) -> u32 {
        match self {
            Self::Merkle { input, .. } => input.subtree_height,
            _ => 0,
        }
    }

    /// Decoded parameter set (None for the parameterless commands).
    pub fn decoded_param(&self) -> Result<Option<ParamSet>, InputError> {
        let command = self.command();
        if !command.takes_param_set() {
            return Ok(None);
        }
        ParamSet::decode(command, self.param_set())
            .map(Some)
            .ok_or(InputError::UnknownParameterSet)
    }

    pub fn payload_bytes(&self) -> Result<usize, InputError> {
        let param = self.decoded_param()?;
        Ok(payload_bytes(
            self.command(),
            param.as_ref(),
            self.subtree_height(),
        ))
    }

    /// Encode the command input exactly as the engine expects it: fixed-size
    /// fields, unused tail bytes zero, integers little-endian. `out` must be
    /// `command().input_len()` bytes. The same range checks the engine makes
    /// (§4 step 7) are made here so a driver bug is caught before submission.
    pub fn encode_input(&self, out: &mut [u8]) -> Result<(), InputError> {
        out.fill(0);
        let param = self.decoded_param()?;
        match (self, param) {
            (Self::SlhSign { input, .. }, Some(ParamSet::Slh(p))) => {
                if out.len() != SLH_SIGN_INPUT_BYTES
                    || input.sk_seed.len() != p.n
                    || input.pk_seed.len() != p.n
                    || input.pk_root.len() != p.n
                    || input.md.len() != p.md_bytes()
                {
                    return Err(InputError::FieldLength);
                }
                if input.idx_tree >> p.idx_tree_bits() != 0 || input.idx_leaf >> p.hp != 0 {
                    return Err(InputError::IndexRange);
                }
                out[0..p.n].copy_from_slice(input.sk_seed);
                out[32..32 + p.n].copy_from_slice(input.pk_seed);
                out[64..64 + p.n].copy_from_slice(input.pk_root);
                out[96..96 + input.md.len()].copy_from_slice(input.md);
                put_u64(out, 144, input.idx_tree);
                put_u32(out, 152, input.idx_leaf);
                Ok(())
            }
            (Self::SlhKeygen { input, .. }, Some(ParamSet::Slh(p))) => {
                if out.len() != SLH_KEYGEN_INPUT_BYTES
                    || input.sk_seed.len() != p.n
                    || input.pk_seed.len() != p.n
                {
                    return Err(InputError::FieldLength);
                }
                out[0..p.n].copy_from_slice(input.sk_seed);
                out[32..32 + p.n].copy_from_slice(input.pk_seed);
                Ok(())
            }
            (Self::Merkle { input, .. }, Some(param)) => {
                if out.len() != MERKLE_INPUT_BYTES || input.seed.len() != param.n() {
                    return Err(InputError::FieldLength);
                }
                let public_len = match param {
                    ParamSet::Lms(_) => 16,
                    _ => param.n(),
                };
                if input.public.len() != public_len {
                    return Err(InputError::FieldLength);
                }
                let height = param.merkle_height().ok_or(InputError::UnknownParameterSet)?;
                if !merkle_range_ok(&param, height, input) {
                    return Err(InputError::IndexRange);
                }
                out[0..input.seed.len()].copy_from_slice(input.seed);
                out[32..32 + input.public.len()].copy_from_slice(input.public);
                put_u32(out, 64, input.subtree_height);
                put_u32(out, 68, input.leaf_start);
                put_u32(out, 72, input.auth_leaf);
                put_u32(out, 76, input.layer);
                put_u64(out, 80, input.tree_address);
                Ok(())
            }
            (Self::QueryCaps | Self::Scrub | Self::ResetCore, None) => {
                if out.is_empty() {
                    Ok(())
                } else {
                    Err(InputError::FieldLength)
                }
            }
            _ => Err(InputError::UnknownParameterSet),
        }
    }
}

/// MERKLE_SUBTREE range rules (ABI.md §6.3, header comments).
pub fn merkle_range_ok(param: &ParamSet, height: u32, input: &MerkleInput<'_>) -> bool {
    let k = input.subtree_height;
    if k > height || height > 31 {
        return false;
    }
    let span = 1u64 << k;
    let start = u64::from(input.leaf_start);
    if start % span != 0 || start + span > (1u64 << height) {
        return false;
    }
    if input.auth_leaf != AUTH_LEAF_NONE {
        let leaf = u64::from(input.auth_leaf);
        if leaf < start || leaf >= start + span {
            return false;
        }
    }
    match param {
        ParamSet::Lms(_) => input.layer == 0 && input.tree_address == 0,
        ParamSet::Xmss(p) => {
            if input.layer >= p.d {
                return false;
            }
            // tree_address < 2^(h − (layer+1)·h/d)
            let bits = p.full_height - (input.layer + 1) * p.tree_height();
            bits >= 64 || input.tree_address >> bits == 0
        }
        ParamSet::Slh(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Cost model for timeouts (ABI.md §9)
// ---------------------------------------------------------------------------

/// Approximate number of hash invocations (Keccak permutations or SHA-2
/// compressions, upper bound) a command performs. Used only to size the first
/// timeout of a (command, param set, k) before its wall time has been learned.
pub fn estimated_hash_ops(command: Command, param: Option<&ParamSet>, k: u32) -> u64 {
    match (command, param) {
        (Command::SlhSign, Some(ParamSet::Slh(p))) => {
            let (n_leaves_fors, a) = (1u64 << p.a, p.a as u64);
            let fors = p.k as u64 * (2 * n_leaves_fors + (1u64 << a));
            let tree = (1u64 << p.hp) * (p.len as u64 * 16 + 2) * 2;
            fors + p.d as u64 * tree
        }
        (Command::SlhKeygen, Some(ParamSet::Slh(p))) => {
            (1u64 << p.hp) * (p.len as u64 * 16 + 2) * 2
        }
        (Command::MerkleSubtree, Some(ParamSet::Lms(p))) => {
            let per_leaf = p.chains() * ((1u64 << p.w) + 1) + 2;
            (1u64 << k) * per_leaf * 2
        }
        (Command::MerkleSubtree, Some(ParamSet::Xmss(p))) => {
            // key PRF + mask PRF + F per chain step, plus the L-tree.
            let per_leaf = p.wots_len() * (15 * 3 + 1) + p.wots_len() * 3;
            (1u64 << k) * per_leaf * 2
        }
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------
pub(crate) fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed width"))
}
pub(crate) fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed width"))
}
pub(crate) fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed width"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_sizes_match_the_header() {
        // hashsig_abi.hpp slh_sign_payload_bytes().
        for (id, bytes) in [
            (1, 7856 - 16),
            (2, 7856 - 16),
            (5, 16224 - 24),
            (6, 16224 - 24),
            (9, 29792 - 32),
            (10, 29792 - 32),
        ] {
            assert_eq!(slh_param(id).unwrap().payload_bytes(), bytes, "param {id}");
        }
        // FIPS 205 Table 2 signature sizes of the f sets.
        for (id, sig) in [(3, 17088), (7, 35664), (11, 49856)] {
            assert_eq!(slh_param(id).unwrap().signature_bytes(), sig, "param {id}");
        }
        // md bytes (ABI.md §7.1).
        assert_eq!(slh_param(2).unwrap().md_bytes(), 21);
        assert_eq!(slh_param(6).unwrap().md_bytes(), 30);
        assert_eq!(slh_param(10).unwrap().md_bytes(), 39);
    }

    #[test]
    fn records_round_trip_at_their_offsets() {
        let request = Request {
            magic: REQUEST_MAGIC,
            abi_version: ABI_VERSION,
            header_bytes: 64,
            total_bytes: 64,
            command: 20,
            flags: 0,
            param_set: 2,
            request_id: 0x1122_3344_5566_7788,
            input_offset: 64,
            input_length: 160,
            output_offset: 256,
            output_length: 64 + 7840,
            tenant_tag: 0xabcd,
            reserved: [0; 3],
        };
        let mut bytes = [0u8; 64];
        request.encode(&mut bytes);
        assert_eq!(&bytes[0..4], b"HSR1");
        assert_eq!(get_u64(&bytes, 24), 0x1122_3344_5566_7788);
        assert_eq!(Request::decode(&bytes), request);

        let completion = Completion {
            magic: COMPLETION_MAGIC,
            abi_version: 1,
            record_bytes: 64,
            status: -5,
            fallback_reason: 14,
            request_id: 9,
            command: 20,
            param_set: 2,
            output_bytes: 0,
            tenant_tag: 7,
            total_cycles: 0,
            hash_steps: 12345,
            lanes: 1,
            reserved: 0,
        };
        completion.encode(&mut bytes);
        assert_eq!(&bytes[0..4], b"HSC1");
        assert_eq!(get_u32(&bytes, 8) as i32, -5);
        assert_eq!(Completion::decode(&bytes), completion);
    }

    #[test]
    fn lms_and_xmss_parameter_sets_decode() {
        let p = lms_param(lms_param_set(0x0F, 0x0B)).unwrap(); // SHAKE256 M32 H5 / W4
        assert_eq!((p.family_bit, p.w_bit, p.n, p.height, p.w), (2, 2, 32, 5, 4));
        assert_eq!(p.chains(), 67);
        assert!(lms_param(lms_param_set(0x05, 0x09)).is_none(), "mixed families");
        assert_eq!(lms_param(lms_param_set(0x0A, 0x05)).unwrap().chains(), 200);
        assert_eq!(lms_param(lms_param_set(0x05, 0x01)).unwrap().chains(), 265);
        assert_eq!(lms_param(lms_param_set(0x05, 0x04)).unwrap().chains(), 34);

        let x = xmss_param(xmss_param_set(0x0000_0008)).unwrap(); // XMSS-SHAKE_16_256
        assert_eq!((x.family_bit, x.n, x.full_height, x.d), (2, 32, 16, 1));
        let mt = xmss_param(xmss_param_set(0x0001_0036)).unwrap(); // SHAKE256_60/3_192
        assert_eq!((mt.family_bit, mt.n, mt.full_height, mt.d), (4, 24, 60, 3));
        assert_eq!(mt.tree_height(), 20);
        assert!(xmss_param(xmss_param_set(0x0000_0016)).is_none());
    }

    #[test]
    fn caps_claims_only_what_is_reported() {
        let mut caps = Caps {
            caps_version: 1,
            commands: (1 << 20) | (1 << 23) | (1 << 25),
            slh_sign_sets: (1 << 2) | (1 << 4),
            ..Caps::default()
        };
        assert!(caps.claims(Command::SlhSign, 2, 0));
        assert!(!caps.claims(Command::SlhSign, 4, 0), "f sets are never claimed");
        assert!(!caps.claims(Command::SlhKeygen, 2, 0));
        assert!(!caps.claims(Command::MerkleSubtree, lms_param_set(0x0F, 0x0B), 3));
        caps.commands |= 1 << 24;
        caps.lms_families = 1 << 2;
        caps.lmots_w = 1 << 2;
        caps.lms_max_subtree_height = 10;
        assert!(caps.claims(Command::MerkleSubtree, lms_param_set(0x0F, 0x0B), 5));
        assert!(!caps.claims(Command::MerkleSubtree, lms_param_set(0x0F, 0x0B), 6));
        assert!(!caps.claims(Command::MerkleSubtree, lms_param_set(0x0F, 0x0C), 3));
        let mut bytes = [0u8; 128];
        caps.encode(&mut bytes);
        assert_eq!(Caps::decode(&bytes), caps);
    }

    #[test]
    fn input_encoding_pads_and_range_checks() {
        let p = slh_param(2).unwrap();
        let (sk, pk, root, md) = ([1u8; 16], [2u8; 16], [3u8; 16], [4u8; 21]);
        let op = Operation::SlhSign {
            param: 2,
            input: SlhSignInput {
                sk_seed: &sk,
                pk_seed: &pk,
                pk_root: &root,
                md: &md,
                idx_tree: (1 << 54) - 1,
                idx_leaf: 511,
            },
        };
        let mut out = [0xffu8; 160];
        op.encode_input(&mut out).unwrap();
        assert_eq!(&out[0..16], &sk);
        assert!(out[16..32].iter().all(|b| *b == 0));
        assert_eq!(&out[96..117], &md);
        assert!(out[117..144].iter().all(|b| *b == 0));
        assert_eq!(get_u64(&out, 144), (1 << 54) - 1);
        assert_eq!(get_u32(&out, 152), 511);
        assert_eq!(op.payload_bytes().unwrap(), p.payload_bytes());

        let bad = Operation::SlhSign {
            param: 2,
            input: SlhSignInput {
                idx_leaf: 512,
                ..match op {
                    Operation::SlhSign { input, .. } => input,
                    _ => unreachable!(),
                }
            },
        };
        assert_eq!(bad.encode_input(&mut out), Err(InputError::IndexRange));
        assert!(out.iter().all(|b| *b == 0), "a rejected input leaves no secret behind");

        let seed = [9u8; 32];
        let id = [8u8; 16];
        let merkle = |k, start, auth| Operation::Merkle {
            param: lms_param_set(0x0F, 0x0B),
            input: MerkleInput {
                seed: &seed,
                public: &id,
                subtree_height: k,
                leaf_start: start,
                auth_leaf: auth,
                layer: 0,
                tree_address: 0,
            },
        };
        let mut out = [0u8; 128];
        merkle(5, 0, AUTH_LEAF_NONE).encode_input(&mut out).unwrap();
        assert_eq!(merkle(5, 0, 3).payload_bytes().unwrap(), 32 * 6);
        assert_eq!(merkle(2, 6, AUTH_LEAF_NONE).encode_input(&mut out), Err(InputError::IndexRange));
        assert_eq!(merkle(2, 4, 3).encode_input(&mut out), Err(InputError::IndexRange));
        assert_eq!(merkle(6, 0, AUTH_LEAF_NONE).encode_input(&mut out), Err(InputError::IndexRange));
    }
}
