mod mock_gps {
    pub mod gps {
        pub fn enable() -> Result<(), &'static str> { Ok(()) }
        pub fn disable() -> Result<(), &'static str> { Ok(()) }
    }
    pub mod location {
        pub fn get_coordinates() -> Result<(f32, f32), &'static str> { Ok((0.0, 0.0)) }
    }
}
use mock_gps as gps;

#[test]
fn test_gnss_enable_disable() {
    gps::gps::enable().expect("Enable failed");
    gps::gps::disable().expect("Disable failed");
}

#[test]
fn test_location_coordinates() {
    gps::gps::enable().expect("Enable failed");
    let (lat, lon) = gps::location::get_coordinates().expect("Coords failed");
    assert!(lat >= -90.0 && lat <= 90.0);
    assert!(lon >= -180.0 && lon <= 180.0);
}
