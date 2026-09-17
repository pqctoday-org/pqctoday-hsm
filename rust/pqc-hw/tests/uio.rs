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
