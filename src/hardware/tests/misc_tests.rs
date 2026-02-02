mod mock_misc {
    pub mod led {
        pub fn enable() -> Result<(), &'static str> { Ok(()) }
    }
    pub mod vibration_motor {
        pub fn vibrate(_intensity: u32) -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_misc as misc;

#[test]
fn test_led_control() {
    misc::led::enable().expect("LED failed");
}

#[test]
fn test_vibrator() {
    misc::vibration_motor::vibrate(100).expect("Vibration failed");
}
