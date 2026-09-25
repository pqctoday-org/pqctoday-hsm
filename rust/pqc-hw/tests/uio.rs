#![cfg(unix)]

use pqc_hw::uio::Mapping;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn discovers_control_window_by_address() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("pqc-uio-{}-{nonce}", std::process::id()));
    for (name, address) in [("uio0", "0x80000000\n"), ("uio1", "0xa0000000\n")] {
        let map = root.join(name).join("maps/map0");
        fs::create_dir_all(&map).unwrap();
        fs::write(map.join("addr"), address).unwrap();
    }
    assert_eq!(
        Mapping::find_by_address(&root, 0xa000_0000).unwrap(),
        std::path::PathBuf::from("/dev/uio1")
    );
    assert!(Mapping::find_by_address(&root, 0xb000_0000).is_err());
    fs::remove_dir_all(root).unwrap();
}

/// The UIO interrupt plumbing (unmask write, ppoll, 4-byte event read) on a
/// FIFO standing in for /dev/uioN: a write shows up as one pending event.
#[test]
fn uio_interrupt_unmask_poll_and_drain() {
    use pqc_hw::mldsa_sign::Interrupt;
    use pqc_hw::uio::UioInterrupt;
    use std::time::Duration;
    let path = std::env::temp_dir().join(format!("pqc-hw-uio-irq-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let mut irq = UioInterrupt::open(&path).unwrap();
    assert!(!irq.wait(Duration::from_millis(5)).unwrap(), "no event yet");
    irq.unmask().unwrap();
    assert!(irq.wait(Duration::from_millis(50)).unwrap(), "one event pending");
    assert!(!irq.wait(Duration::ZERO).unwrap(), "consumed");
    irq.unmask().unwrap();
    irq.unmask().unwrap();
    irq.drain().unwrap();
    assert!(!irq.wait(Duration::ZERO).unwrap(), "drained");
    fs::remove_file(&path).unwrap();
}
