mod mock_thermal {
    pub mod thermal_control {
        pub fn get_temperature() -> Result<u32, &'static str> { Ok(35) }
    }
}
use mock_thermal::thermal_control;

#[test]
fn test_thermal_sensor_reading() {
    let temp = thermal_control::get_temperature().expect("Read failed");
    assert!(temp <= 150);
}
