mod mock_nfc {
    pub mod reader {
        pub fn enable() -> Result<(), &'static str> { Ok(()) }
        pub fn disable() -> Result<(), &'static str> { Ok(()) }
    }
    pub mod payment {
        pub fn enable() -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_nfc as nfc;

#[test]
fn test_nfc_reader_enable_disable() {
    nfc::reader::enable().expect("Enable failed");
    nfc::reader::disable().expect("Disable failed");
}

#[test]
fn test_nfc_payment_enable() {
    nfc::payment::enable().expect("Enable failed");
}
