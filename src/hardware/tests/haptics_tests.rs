mod mock_haptics {
    pub mod haptics_control {
        pub fn vibrate(_intensity: u32) -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_haptics as haptics;

#[test]
fn test_haptics_vibration() {
    haptics::haptics_control::vibrate(100).expect("Haptics failed");
}
