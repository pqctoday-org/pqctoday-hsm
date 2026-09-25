use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

/// How cache maintenance reaches the u-dma-buf driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMethod {
    /// Three sysfs writes per sync (`sync_offset`, `sync_size`, then the
    /// `sync_for_*` trigger), each an open/write/close.
    Sysfs,
    /// One `ioctl` on the already-open device carrying offset, size and
    /// direction (`U_DMA_BUF_IOCTL_SET_SYNC_FOR_{CPU,DEVICE}`, u-dma-buf
    /// ioctl version >= 1; the KV260 image pins u-dma-buf 5.5.0, whose
    /// default build has ioctl version 2). The shared sysfs `sync_offset` /
    /// `sync_size` defaults are not touched.
    Ioctl,
}

// u-dma-buf 5.5.0 `u-dma-buf-ioctl.h` (Linux asm-generic _IOC encoding).
const UDMABUF_IOCTL_GET_DRV_INFO: u64 = (2 << 30) | (24 << 16) | (0x55 << 8) | 1;
const UDMABUF_IOCTL_SET_SYNC_FOR_CPU: u64 = (1 << 30) | (8 << 16) | (0x55 << 8) | 5;
const UDMABUF_IOCTL_SET_SYNC_FOR_DEVICE: u64 = (1 << 30) | (8 << 16) | (0x55 << 8) | 6;
const SYNC_LINE: usize = 64;

/// The u-dma-buf per-command sync argument: offset in bits 63..32, size in
/// bits 31..4 (a multiple of 16), direction in bits 3..2 (0 = bidirectional,
/// as the sysfs default `sync_direction` is), bit 0 set. The range is
/// widened to whole 64-byte cache lines, clamped to the allocation.
pub fn sync_command(buffer_len: usize, offset: usize, len: usize) -> io::Result<u64> {
    validate_range(buffer_len, offset, len)?;
    let start = offset / SYNC_LINE * SYNC_LINE;
    let end = (offset + len).div_ceil(SYNC_LINE) * SYNC_LINE;
    let end = end.min(buffer_len);
    let size = end - start;
    if start > u32::MAX as usize || size > 0xffff_fff0 || !size.is_multiple_of(16) || size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DMA synchronization range cannot be encoded",
        ));
    }
    Ok(((start as u64) << 32) | size as u64 | 1)
}

/// Mapping for the out-of-tree u-dma-buf device expected by the K26 image.
/// Physical addresses come from sysfs and are never guessed from virtual
/// addresses. The complete region is cleared before unmapping.
pub struct Buffer {
    ptr: NonNull<u8>,
    len: usize,
    phys_addr: u64,
    sysfs: PathBuf,
    cleared: bool,
    sync: SyncMethod,
    _file: File,
}

impl Buffer {
    pub fn open(device: impl AsRef<Path>, sysfs: impl AsRef<Path>) -> io::Result<Self> {
        let device = device.as_ref();
        let sysfs = sysfs.as_ref();
        let len = parse_number(sysfs.join("size"))? as usize;
        let phys_addr = parse_number(sysfs.join("phys_addr"))?;
        if len == 0 || phys_addr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DMA buffer metadata",
            ));
        }
        let file = OpenOptions::new().read(true).write(true).open(device)?;
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let sync = select_sync_method(&file, len);
        Ok(Self {
            ptr: NonNull::new(raw.cast()).expect("mmap returned null"),
            len,
            phys_addr,
            sysfs: sysfs.to_path_buf(),
            cleared: false,
            sync,
            _file: file,
        })
    }

    pub fn sync_method(&self) -> SyncMethod {
        self.sync
    }

    pub fn phys_addr(&self) -> u64 {
        self.phys_addr
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.cleared = false;
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn clear(&mut self) -> io::Result<()> {
        if self.cleared {
            return Ok(());
        }
        // mmap is page-aligned. Clear a word at a time while keeping each
        // store observable; byte-wide volatile stores made teardown of the
        // 1 MiB K26 allocation dominate every short accelerator request.
        let words = self.len / std::mem::size_of::<u64>();
        for index in 0..words {
            unsafe { std::ptr::write_volatile(self.ptr.as_ptr().cast::<u64>().add(index), 0) }
        }
        for index in words * std::mem::size_of::<u64>()..self.len {
            unsafe { std::ptr::write_volatile(self.ptr.as_ptr().add(index), 0) }
        }
        // msync returns EINVAL for u-dma-buf on the KV260. Explicitly flush
        // the zeroes to device-visible DDR before allowing the next request.
        self.sync_range_for_device(0, self.len)?;
        self.cleared = true;
        Ok(())
    }

    pub fn sync_for_device(&self) -> io::Result<()> {
        self.sync_range_for_device(0, self.len)
    }

    pub fn sync_for_cpu(&mut self) -> io::Result<()> {
        self.sync_range_for_cpu(0, self.len)
    }

    pub fn sync_range_for_device(&self, offset: usize, len: usize) -> io::Result<()> {
        if self.sync == SyncMethod::Ioctl {
            return self.ioctl_sync(UDMABUF_IOCTL_SET_SYNC_FOR_DEVICE, offset, len);
        }
        self.configure_sync_range(offset, len)?;
        self.trigger_sync("sync_for_device")
    }

    pub fn sync_range_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()> {
        if self.sync == SyncMethod::Ioctl {
            self.ioctl_sync(UDMABUF_IOCTL_SET_SYNC_FOR_CPU, offset, len)?;
        } else {
            self.configure_sync_range(offset, len)?;
            self.trigger_sync("sync_for_cpu")?;
        }
        self.cleared = false;
        Ok(())
    }

    fn ioctl_sync(&self, request: u64, offset: usize, len: usize) -> io::Result<()> {
        let command = sync_command(self.len, offset, len)?;
        // SAFETY: the request takes a pointer to one u64 that it only reads.
        let rc = unsafe {
            libc::ioctl(self._file.as_raw_fd(), request as _, &command as *const u64)
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn clear_range(&mut self, offset: usize, len: usize) -> io::Result<()> {
        validate_range(self.len, offset, len)?;
        let words = len / std::mem::size_of::<u64>();
        for index in 0..words {
            unsafe {
                std::ptr::write_volatile(self.ptr.as_ptr().add(offset).cast::<u64>().add(index), 0)
            }
        }
        for index in words * std::mem::size_of::<u64>()..len {
            unsafe { std::ptr::write_volatile(self.ptr.as_ptr().add(offset + index), 0) }
        }
        self.sync_range_for_device(offset, len)?;
        Ok(())
    }

    fn configure_sync_range(&self, offset: usize, len: usize) -> io::Result<()> {
        validate_range(self.len, offset, len)?;
        std::fs::write(self.sysfs.join("sync_offset"), format!("0x{offset:x}\n"))?;
        std::fs::write(self.sysfs.join("sync_size"), format!("{len}\n"))
    }

    fn trigger_sync(&self, name: &str) -> io::Result<()> {
        std::fs::write(self.sysfs.join(name), "1\n")
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if let Err(error) = self.clear() {
            eprintln!("PQC DMA zeroization sync failed: {error}");
        }
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

/// `PQC_HW_DMA_SYNC=sysfs` forces the sysfs path; otherwise the ioctl path
/// is used when the driver answers `GET_DRV_INFO` with ioctl version >= 1
/// and the allocation fits the 32-bit command encoding.
fn select_sync_method(file: &File, len: usize) -> SyncMethod {
    if std::env::var("PQC_HW_DMA_SYNC").is_ok_and(|v| v == "sysfs") || len > u32::MAX as usize {
        return SyncMethod::Sysfs;
    }
    #[repr(C)]
    struct DrvInfo {
        flags: u64,
        version: [u8; 16],
    }
    let mut info = DrvInfo {
        flags: 0,
        version: [0; 16],
    };
    // SAFETY: GET_DRV_INFO writes one 24-byte struct into `info`; any other
    // file rejects the request (ENOTTY/EINVAL) without touching it.
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            UDMABUF_IOCTL_GET_DRV_INFO as _,
            &mut info as *mut DrvInfo,
        )
    };
    if rc == 0 && info.flags & 0xff >= 1 {
        SyncMethod::Ioctl
    } else {
        SyncMethod::Sysfs
    }
}

fn parse_number(path: PathBuf) -> io::Result<u64> {
    let mut text = String::new();
    File::open(path)?.read_to_string(&mut text)?;
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    parsed.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn validate_range(buffer_len: usize, offset: usize, len: usize) -> io::Result<()> {
    if len == 0 || offset.checked_add(len).is_none_or(|end| end > buffer_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DMA synchronization range is outside the allocation",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{sync_command, validate_range};

    #[test]
    fn sync_commands_encode_whole_lines_offset_and_size() {
        // SIGN device extent: request + input, already line-aligned.
        assert_eq!(sync_command(1 << 20, 0, 0x100 + 17_536).unwrap(), 0x4580 | 1);
        // Completion + signature at 0x8000: 3,437 bytes widen to 3,456.
        assert_eq!(
            sync_command(1 << 20, 0x8000, 3_437).unwrap(),
            (0x8000u64 << 32) | 3_456 | 1
        );
        // Unaligned start widens down; the end is clamped to the allocation.
        assert_eq!(
            sync_command(1 << 20, (1 << 20) - 10, 10).unwrap(),
            (((1u64 << 20) - 64) << 32) | 64 | 1
        );
        assert!(sync_command(1 << 20, 0, 0).is_err());
        assert!(sync_command(1 << 20, 1 << 20, 1).is_err());
    }

    #[test]
    fn validates_bounded_nonempty_dma_ranges() {
        assert!(validate_range(1024, 0, 1024).is_ok());
        assert!(validate_range(1024, 64, 128).is_ok());
        assert!(validate_range(1024, 0, 0).is_err());
        assert!(validate_range(1024, 1024, 1).is_err());
        assert!(validate_range(1024, usize::MAX, 2).is_err());
    }
}
