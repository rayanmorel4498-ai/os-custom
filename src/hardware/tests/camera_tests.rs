#[path = "hardware_simulator.rs"]
mod hardware_simulator;

use hardware_simulator::sim_reset;

// Advanced camera subsystem with state management
mod mock_camera {
    use std::sync::{Arc, Mutex};

    pub struct CameraState {
        pub rear_enabled: bool,
        pub rear_resolution: u16,
        pub rear_fps: u8,
        pub rear_frames_captured: u32,
        pub front_enabled: bool,
        pub front_resolution: u16,
        pub flash_enabled: bool,
        pub flash_brightness: u8,
        pub zoom_level: u8,
        pub stabilization_active: bool,
    }

    impl CameraState {
        pub fn new() -> Self {
            CameraState {
                rear_enabled: false,
                rear_resolution: 1920,
                rear_fps: 30,
                rear_frames_captured: 0,
                front_enabled: false,
                front_resolution: 1080,
                flash_enabled: false,
                flash_brightness: 0,
                zoom_level: 1,
                stabilization_active: false,
            }
        }

        pub fn reset(&mut self) {
            *self = CameraState::new();
        }
    }

    lazy_static::lazy_static! {
        pub static ref STATE: Arc<Mutex<CameraState>> = Arc::new(Mutex::new(CameraState::new()));
    }

    pub mod rear_camera {
        use super::STATE;

        pub fn init() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.rear_enabled = true;
            Ok(())
        }

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.rear_enabled = true;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.rear_enabled = false;
            state.rear_frames_captured = 0;
            Ok(())
        }

        pub fn capture() -> Result<u32, &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.rear_enabled {
                return Err("Rear camera not enabled");
            }
            state.rear_frames_captured += 1;
            Ok(state.rear_frames_captured)
        }

        pub fn set_resolution(width: u16) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if width < 640 || width > 4096 {
                return Err("Resolution out of range");
            }
            state.rear_resolution = width;
            Ok(())
        }

        pub fn set_fps(fps: u8) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if fps < 15 || fps > 240 {
                return Err("FPS out of range");
            }
            state.rear_fps = fps;
            Ok(())
        }

        pub fn get_frames_captured() -> u32 {
            let state = STATE.lock().unwrap();
            state.rear_frames_captured
        }

        pub fn stop() -> Result<(), &'static str> {
            disable()
        }
    }

    pub mod front_camera {
        use super::STATE;

        pub fn init() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.front_enabled = true;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.front_enabled = false;
            Ok(())
        }

        pub fn capture() -> Result<u32, &'static str> {
            let state = STATE.lock().unwrap();
            if !state.front_enabled {
                return Err("Front camera not enabled");
            }
            Ok(state.front_resolution as u32)
        }
    }

    pub mod flash {
        use super::STATE;

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.flash_enabled = true;
            state.flash_brightness = 255;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.flash_enabled = false;
            state.flash_brightness = 0;
            Ok(())
        }

        pub fn set_brightness(brightness: u8) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.flash_enabled {
                return Err("Flash not enabled");
            }
            state.flash_brightness = brightness;
            Ok(())
        }

        pub fn get_brightness() -> u8 {
            let state = STATE.lock().unwrap();
            state.flash_brightness
        }
    }

    pub mod zoom {
        use super::STATE;

        pub fn set_level(level: u8) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if level < 1 || level > 10 {
                return Err("Zoom level out of range");
            }
            state.zoom_level = level;
            Ok(())
        }

        pub fn get_level() -> u8 {
            let state = STATE.lock().unwrap();
            state.zoom_level
        }
    }

    pub mod stabilization {
        use super::STATE;

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.stabilization_active = true;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.stabilization_active = false;
            Ok(())
        }

        pub fn is_active() -> bool {
            let state = STATE.lock().unwrap();
            state.stabilization_active
        }
    }
}

use mock_camera as camera;

#[test]
fn test_rear_camera_full_lifecycle() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::init().is_ok());
    assert!(camera::rear_camera::capture().is_ok());
    assert_eq!(camera::rear_camera::get_frames_captured(), 1);
    assert!(camera::rear_camera::capture().is_ok());
    assert_eq!(camera::rear_camera::get_frames_captured(), 2);
    assert!(camera::rear_camera::stop().is_ok());
}

#[test]
fn test_rear_camera_resolution_settings() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::init().is_ok());
    assert!(camera::rear_camera::set_resolution(2560).is_ok());
    assert!(camera::rear_camera::set_resolution(4096).is_ok());
    assert!(camera::rear_camera::set_resolution(10000).is_err());
    assert!(camera::rear_camera::set_resolution(100).is_err());
}

#[test]
fn test_rear_camera_enable_disable() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::enable().is_ok());
    assert!(camera::rear_camera::capture().is_ok());
    assert_eq!(camera::rear_camera::get_frames_captured(), 1);
    
    assert!(camera::rear_camera::disable().is_ok());
    assert!(camera::rear_camera::capture().is_err());
}

#[test]
fn test_rear_camera_fps_control() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::init().is_ok());
    assert!(camera::rear_camera::set_fps(60).is_ok());
    assert!(camera::rear_camera::set_fps(240).is_ok());
    assert!(camera::rear_camera::set_fps(10).is_err());
    assert!(camera::rear_camera::set_fps(255).is_err());
}

#[test]
fn test_rear_camera_disabled_capture() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::capture().is_err());
    assert!(camera::rear_camera::init().is_ok());
    assert!(camera::rear_camera::disable().is_ok());
    assert!(camera::rear_camera::capture().is_err());
}

#[test]
fn test_front_camera_lifecycle() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::front_camera::init().is_ok());
    assert!(camera::front_camera::capture().is_ok());
    assert!(camera::front_camera::disable().is_ok());
    assert!(camera::front_camera::capture().is_err());
}

#[test]
fn test_flash_brightness_control() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::flash::enable().is_ok());
    assert_eq!(camera::flash::get_brightness(), 255);
    
    assert!(camera::flash::set_brightness(128).is_ok());
    assert_eq!(camera::flash::get_brightness(), 128);
    
    assert!(camera::flash::set_brightness(0).is_ok());
    assert!(camera::flash::disable().is_ok());
    assert_eq!(camera::flash::get_brightness(), 0);
}

#[test]
fn test_flash_disabled_brightness() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::flash::disable().is_ok());
    assert!(camera::flash::set_brightness(100).is_err());
}

#[test]
fn test_zoom_levels() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert_eq!(camera::zoom::get_level(), 1);
    
    for level in 2..=10 {
        assert!(camera::zoom::set_level(level).is_ok());
        assert_eq!(camera::zoom::get_level(), level);
    }
    
    assert!(camera::zoom::set_level(0).is_err());
    assert!(camera::zoom::set_level(11).is_err());
}

#[test]
fn test_stabilization_control() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(!camera::stabilization::is_active());
    assert!(camera::stabilization::enable().is_ok());
    assert!(camera::stabilization::is_active());
    assert!(camera::stabilization::disable().is_ok());
    assert!(!camera::stabilization::is_active());
}

#[test]
fn test_camera_multi_capture() {
    sim_reset();
    let mut state = mock_camera::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(camera::rear_camera::init().is_ok());
    
    let mut count = 0;
    for _ in 0..100 {
        if let Ok(_) = camera::rear_camera::capture() {
            count += 1;
        }
    }
    
    assert_eq!(count, 100);
    assert_eq!(camera::rear_camera::get_frames_captured(), 100);
}
