//! Linux UIO + u-dma-buf transport for hashsig engine instances.
//!
//! Discovery follows ABI.md §2 and the `hashsig` profile overlay
//! (`fpga/hashsig/vivado/pqc-hashsig-behaviour-overlay.dts`): the control
//! window is the `generic-uio` node `hashsig@a0100000` (UIO map 0 at
//! `0xA0100000`, 64 KiB) and the DMA buffer is the `ikwzm,u-dma-buf` device
//! `pqc-hashsig-dma0` with lock file `/run/lock/pqc-hashsig-dma0.lock`
//! (`profile.manifest.in`). In the `mldsa` profile no UIO map sits at that
//! address, so discovery fails before anything is created or locked and every
//! operation stays on ARM (plan §3.3).

use super::abi::{Caps, Operation, UIO_ENGINE0_BASE, UIO_WINDOW_BYTES};
use super::pool::Lane;
use super::{Engine, Error, Health, Output};
use crate::dma::Buffer;
use crate::uio::Mapping;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// One engine instance's resources.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    pub control_base: u64,
    /// UIO `name` (the device-tree node name of the `generic-uio` node).
    pub uio_name: &'static str,
    pub dma_device: &'static str,
    pub dma_sysfs: &'static str,
    pub lock_path: &'static str,
}

/// v1 builds one engine instance. Engine 1 (`0xA0110000`) is reserved by the
/// ABI but has no overlay node or DMA buffer, so it is not listed.
pub const ENGINES: [EngineConfig; 1] = [EngineConfig {
    control_base: UIO_ENGINE0_BASE,
    uio_name: "hashsig",
    dma_device: "/dev/pqc-hashsig-dma0",
    dma_sysfs: "/sys/class/u-dma-buf/pqc-hashsig-dma0",
    lock_path: "/run/lock/pqc-hashsig-dma0.lock",
}];

pub const UIO_SYSFS: &str = "/sys/class/uio";

/// Finds the UIO device whose map 0 starts at `address`. When the device
/// exposes a `name`, it must be `name` or `name@<unit-address>`: generic-uio
/// on the KV260's 6.18 kernel reports the full device-tree node name
/// (`hashsig@a0100000`), older kernels the bare `hashsig`. A map smaller than
/// the ABI window is rejected.
pub fn find_uio(sysfs_root: impl AsRef<Path>, address: u64, name: &str) -> io::Result<PathBuf> {
    for entry in std::fs::read_dir(sysfs_root)? {
        let entry = entry?;
        let path = entry.path();
        let Ok(text) = std::fs::read_to_string(path.join("maps/map0/addr")) else {
            continue;
        };
        if parse_hex(&text) != Some(address) {
            continue;
        }
        if let Ok(found) = std::fs::read_to_string(path.join("name")) {
            let found = found.trim();
            let base = found.split_once('@').map_or(found, |(base, _)| base);
            if !found.is_empty() && base != name {
                continue;
            }
        }
        if let Ok(size) = std::fs::read_to_string(path.join("maps/map0/size"))
            && parse_hex(&size).is_some_and(|size| size < UIO_WINDOW_BYTES as u64) {
                continue;
            }
        return Ok(PathBuf::from("/dev").join(entry.file_name()));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "hashsig engine UIO device not found",
    ))
}

fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
}

/// An open engine instance: register window, DMA buffer and the lock file
/// that makes the DMA allocation process-exclusive (same policy as the
/// ML-DSA lanes).
pub struct HashsigSession {
    engine: Engine<Mapping, Buffer>,
    _lock: File,
}

// The mappings are exclusively owned by the session and every register/DMA
// access requires `&mut self`; shared access still requires the pool's mutex.
unsafe impl Send for HashsigSession {}

impl HashsigSession {
    /// True when the loaded profile has this engine instance (no side effects).
    pub fn present(instance: usize) -> bool {
        ENGINES
            .get(instance)
            .is_some_and(|c| find_uio(UIO_SYSFS, c.control_base, c.uio_name).is_ok())
    }

    pub fn open(instance: usize) -> io::Result<Self> {
        let config = ENGINES.get(instance).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid hashsig engine instance")
        })?;
        // Discover first: in a profile without the engine nothing is created.
        let uio = find_uio(UIO_SYSFS, config.control_base, config.uio_name)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.lock_path)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "hashsig DMA allocation is owned by another process",
            ));
        }
        let dma = Buffer::open(config.dma_device, config.dma_sysfs)?;
        let registers = Mapping::open(uio, UIO_WINDOW_BYTES)?;
        Ok(Self {
            engine: Engine::new(registers, dma)?,
            _lock: lock,
        })
    }

    pub fn engine_mut(&mut self) -> &mut Engine<Mapping, Buffer> {
        &mut self.engine
    }
}

impl Lane for HashsigSession {
    fn execute(&mut self, op: &Operation<'_>) -> Result<Output, Error> {
        self.engine.execute(op, None)
    }
    fn execute_batch(&mut self, ops: &[Operation<'_>]) -> Result<Vec<Result<Output, Error>>, Error> {
        self.engine.execute_batch(ops, None)
    }
    fn max_batch(&self) -> usize {
        self.engine.max_batch()
    }
    fn health(&self) -> Health {
        self.engine.health()
    }
    fn mark_degraded(&mut self) {
        self.engine.mark_degraded();
    }
    fn recover(&mut self, kat: &Operation<'_>, expected: &[u8]) -> Health {
        self.engine.recover(kat, expected)
    }
    fn query_caps(&mut self) -> Result<Caps, Error> {
        self.engine.query_caps()
    }
    fn reset_core(&mut self) -> Result<(), Error> {
        self.engine.execute(&Operation::ResetCore, None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::find_uio;
    use std::fs;

    fn uio(root: &std::path::Path, dev: &str, addr: &str, name: Option<&str>, size: &str) {
        let map = root.join(dev).join("maps/map0");
        fs::create_dir_all(&map).unwrap();
        fs::write(map.join("addr"), addr).unwrap();
        fs::write(map.join("size"), size).unwrap();
        if let Some(name) = name {
            fs::write(root.join(dev).join("name"), format!("{name}\n")).unwrap();
        }
    }

    #[test]
    fn discovers_by_address_and_name() {
        let root = std::env::temp_dir().join(format!("hashsig-uio-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        // mldsa-profile windows and the TCN: never matched.
        uio(&root, "uio0", "0xa0000000\n", Some("mailbox"), "0x2000");
        uio(&root, "uio1", "0xa0060000\n", Some("behaviour"), "0x10000");
        assert!(find_uio(&root, 0xa010_0000, "hashsig").is_err());
        // Right address, wrong name: rejected.
        uio(&root, "uio2", "0xa0100000\n", Some("other"), "0x10000");
        assert!(find_uio(&root, 0xa010_0000, "hashsig").is_err());
        uio(&root, "uio3", "0xa0100000\n", Some("hashsig"), "0x10000");
        assert_eq!(
            find_uio(&root, 0xa010_0000, "hashsig").unwrap(),
            std::path::PathBuf::from("/dev/uio3")
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// The KV260's 6.18 kernel names a generic-uio device after the full
    /// device-tree node, `hashsig@a0100000` (seen on the board 2026-09-25);
    /// `hashsig-other` or `other@a0100000` must still be rejected.
    #[test]
    fn accepts_node_name_with_unit_address() {
        let root = std::env::temp_dir().join(format!("hashsig-uio-at-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        uio(&root, "uio4", "0x00000000a0100000\n", Some("other@a0100000"), "0x10000");
        uio(&root, "uio5", "0x00000000a0100000\n", Some("hashsig-other"), "0x10000");
        assert!(find_uio(&root, 0xa010_0000, "hashsig").is_err());
        uio(&root, "uio6", "0x00000000a0100000\n", Some("hashsig@a0100000"), "0x10000");
        assert_eq!(
            find_uio(&root, 0xa010_0000, "hashsig").unwrap(),
            std::path::PathBuf::from("/dev/uio6")
        );
        let _ = fs::remove_dir_all(&root);
    }
}
