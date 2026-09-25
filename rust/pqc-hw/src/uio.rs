use crate::keccak::RegisterIo;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;

pub struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
    _file: File,
}
impl Mapping {
    pub fn find_by_address(sysfs_root: impl AsRef<Path>, expected: u64) -> io::Result<PathBuf> {
        for entry in std::fs::read_dir(sysfs_root)? {
            let entry = entry?;
            let address = std::fs::read_to_string(entry.path().join("maps/map0/addr"));
            let Some(address) = address.ok() else {
                continue;
            };
            let address = address.trim().trim_start_matches("0x");
            if u64::from_str_radix(address, 16).ok() == Some(expected) {
                return Ok(PathBuf::from("/dev").join(entry.file_name()));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "FPGA UIO device not found",
        ))
    }
    pub fn open(path: impl AsRef<Path>, len: usize) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
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
            _file: file,
        })
    }
}
impl RegisterIo for Mapping {
    fn read32(&mut self, offset: usize) -> u32 {
        assert!(offset <= self.len - 4 && offset.is_multiple_of(4));
        unsafe { std::ptr::read_volatile(self.ptr.as_ptr().add(offset).cast::<u32>()) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        assert!(offset <= self.len - 4 && offset.is_multiple_of(4));
        unsafe { std::ptr::write_volatile(self.ptr.as_ptr().add(offset).cast::<u32>(), value) }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

/// The interrupt line of one `generic-uio` device (`uio_pdrv_genirq`):
/// writing 1 re-enables the line, `read` returns the event count once an
/// interrupt has fired (the kernel handler disables the line again).
pub struct UioInterrupt {
    file: File,
}

impl UioInterrupt {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file })
    }

    fn poll(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let mut fd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        // SAFETY: one valid pollfd, a valid timespec, no signal mask.
        let rc = unsafe { libc::ppoll(&mut fd, 1, &ts, std::ptr::null()) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        if rc > 0 && fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("UIO interrupt poll error"));
        }
        Ok(rc > 0 && fd.revents & libc::POLLIN != 0)
    }

    fn consume(&mut self) -> io::Result<()> {
        let mut count = [0u8; 4];
        let n = std::io::Read::read(&mut self.file, &mut count)?;
        if n != 4 {
            return Err(io::Error::other("short UIO event read"));
        }
        Ok(())
    }
}

impl crate::mldsa_sign::Interrupt for UioInterrupt {
    fn drain(&mut self) -> io::Result<()> {
        while self.poll(std::time::Duration::ZERO)? {
            self.consume()?;
        }
        Ok(())
    }

    fn unmask(&mut self) -> io::Result<()> {
        let n = std::io::Write::write(&mut self.file, &1u32.to_ne_bytes())?;
        if n != 4 {
            return Err(io::Error::other("short UIO irqcontrol write"));
        }
        Ok(())
    }

    fn wait(&mut self, timeout: std::time::Duration) -> io::Result<bool> {
        if self.poll(timeout)? {
            self.consume()?;
            return Ok(true);
        }
        Ok(false)
    }
}
