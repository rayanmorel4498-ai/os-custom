mod mock_storage {
    pub mod flash {
        pub fn read(_addr: u32, _size: u32) -> Result<(), &'static str> { Ok(()) }
        pub fn write(_addr: u32, _data: &[u8]) -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_storage as storage;

#[test]
fn test_flash_read() {
    storage::flash::read(0x1000, 256).expect("Read failed");
}

#[test]
fn test_flash_write() {
    let data = vec![0xAA; 256];
    storage::flash::write(0x2000, &data).expect("Write failed");
}
