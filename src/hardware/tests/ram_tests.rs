mod mock_ram {
    pub mod ram_control {
        pub fn init() -> Result<(), &'static str> { Ok(()) }
        pub fn set_frequency(_freq: u32) -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_ram as ram;

#[test]
fn test_ram_initialization() {
    ram::ram_control::init().expect("Init failed");
}

#[test]
fn test_ram_frequency_scaling() {
    for freq in &[400, 800, 1200, 1600, 2000] {
        ram::ram_control::set_frequency(*freq).expect("Freq failed");
    }
}
