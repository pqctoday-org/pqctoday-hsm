#![cfg(unix)]

use pqc_hw::dma::Buffer;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn maps_metadata_and_zeroizes_on_drop() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("pqc-hw-dma-{}-{nonce}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let device = root.join("udmabuf0");
    let sysfs = root.join("sysfs");
    fs::create_dir(&sysfs).unwrap();
    let file = File::create(&device).unwrap();
    file.set_len(4096).unwrap();
    fs::write(sysfs.join("size"), "4096\n").unwrap();
    fs::write(sysfs.join("phys_addr"), "0x12345000\n").unwrap();
    fs::write(sysfs.join("sync_for_device"), "").unwrap();
    fs::write(sysfs.join("sync_for_cpu"), "").unwrap();

    {
        let mut buffer = Buffer::open(&device, &sysfs).unwrap();
        assert_eq!(buffer.phys_addr(), 0x12345000);
        buffer.as_mut_slice()[0..4].copy_from_slice(b"KEY!");
        buffer.sync_for_device().unwrap();
        buffer.sync_for_cpu().unwrap();
    }

    assert_eq!(
        fs::read_to_string(sysfs.join("sync_for_device")).unwrap(),
        "1\n"
    );
    assert_eq!(
        fs::read_to_string(sysfs.join("sync_for_cpu")).unwrap(),
        "1\n"
    );

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = [0xff; 4];
    file.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0; 4]);
    file.write_all(&[]).unwrap();
    fs::remove_dir_all(root).unwrap();
}
