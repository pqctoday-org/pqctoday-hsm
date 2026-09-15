use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

/// Mapping for the out-of-tree u-dma-buf device expected by the K26 image.
/// Physical addresses come from sysfs and are never guessed from virtual
/// addresses. The complete region is cleared before unmapping.
pub struct Buffer {
    ptr: NonNull<u8>,
    len: usize,
    phys_addr: u64,
    sysfs: PathBuf,
    cleared: bool,
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
        Ok(Self {
            ptr: NonNull::new(raw.cast()).expect("mmap returned null"),
            len,
            phys_addr,
            sysfs: sysfs.to_path_buf(),
            cleared: false,
            _file: file,
        })
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
        self.configure_sync_range(0, self.len)?;
        self.trigger_sync("sync_for_device")?;
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
        self.configure_sync_range(offset, len)?;
        self.trigger_sync("sync_for_device")
    }

    pub fn sync_range_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()> {
        self.configure_sync_range(offset, len)?;
        self.trigger_sync("sync_for_cpu")?;
        self.cleared = false;
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
    use super::validate_range;

    #[test]
    fn validates_bounded_nonempty_dma_ranges() {
        assert!(validate_range(1024, 0, 1024).is_ok());
        assert!(validate_range(1024, 64, 128).is_ok());
        assert!(validate_range(1024, 0, 0).is_err());
        assert!(validate_range(1024, 1024, 1).is_err());
        assert!(validate_range(1024, usize::MAX, 2).is_err());
    }
}
