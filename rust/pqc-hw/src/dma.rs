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
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn clear(&mut self) {
        for index in 0..self.len {
            unsafe { std::ptr::write_volatile(self.ptr.as_ptr().add(index), 0) }
        }
        unsafe {
            libc::msync(self.ptr.as_ptr().cast(), self.len, libc::MS_SYNC);
        }
    }

    pub fn sync_for_device(&self) -> io::Result<()> {
        std::fs::write(self.sysfs.join("sync_for_device"), "1\n")
    }

    pub fn sync_for_cpu(&self) -> io::Result<()> {
        std::fs::write(self.sysfs.join("sync_for_cpu"), "1\n")
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.clear();
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
