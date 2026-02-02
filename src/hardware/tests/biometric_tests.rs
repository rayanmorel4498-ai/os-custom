#[path = "hardware_simulator.rs"]
mod hardware_simulator;

use hardware_simulator::sim_reset;

// Mock biometric subsystem with state management
mod mock_biometric {
    use std::sync::{Arc, Mutex};

    pub struct BiometricState {
        pub fp_enabled: bool,
        pub fp_quality: u8,
        pub fp_templates: u32,
        pub fp_failures: u8,
        pub faceid_enabled: bool,
        pub faceid_confidence: u8,
        pub faceid_attempts: u8,
        pub iris_enabled: bool,
        pub iris_quality: u8,
        pub iris_templates: u32,
    }

    impl BiometricState {
        pub fn new() -> Self {
            BiometricState {
                fp_enabled: false,
                fp_quality: 0,
                fp_templates: 0,
                fp_failures: 0,
                faceid_enabled: false,
                faceid_confidence: 0,
                faceid_attempts: 0,
                iris_enabled: false,
                iris_quality: 0,
                iris_templates: 0,
            }
        }

        pub fn reset(&mut self) {
            *self = BiometricState::new();
        }
    }

    lazy_static::lazy_static! {
        pub static ref STATE: Arc<Mutex<BiometricState>> = Arc::new(Mutex::new(BiometricState::new()));
    }

    pub mod fingerprint {
        use super::STATE;

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.fp_enabled = true;
            state.fp_quality = 85;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.fp_enabled = false;
            state.fp_quality = 0;
            Ok(())
        }

        pub fn get_status() -> u32 {
            let state = STATE.lock().unwrap();
            if state.fp_enabled { 0x1 } else { 0x0 }
        }

        pub fn enroll(template_id: u32) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.fp_enabled {
                return Err("Fingerprint not enabled");
            }
            if template_id > 5 {
                return Err("Template ID out of range");
            }
            state.fp_templates = template_id + 1;
            Ok(())
        }

        pub fn verify(template_id: u32) -> Result<u32, &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.fp_enabled {
                state.fp_failures += 1;
                if state.fp_failures >= 5 {
                    return Err("Fingerprint locked after 5 failures");
                }
                return Err("Fingerprint not enabled");
            }
            if template_id >= state.fp_templates {
                state.fp_failures += 1;
                return Err("Template not found");
            }
            state.fp_failures = 0;
            Ok(1)
        }

        pub fn get_template_count() -> u32 {
            let state = STATE.lock().unwrap();
            state.fp_templates
        }

        pub fn get_attempts() -> u32 {
            let state = STATE.lock().unwrap();
            state.fp_failures as u32
        }
    }

    pub mod faceid {
        use super::STATE;

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.faceid_enabled = true;
            state.faceid_confidence = 95;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.faceid_enabled = false;
            state.faceid_confidence = 0;
            Ok(())
        }

        pub fn unlock_with_face() -> Result<bool, &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.faceid_enabled {
                state.faceid_attempts += 1;
                if state.faceid_attempts >= 5 {
                    return Err("Face recognition locked");
                }
                return Err("Face recognition not enabled");
            }
            state.faceid_attempts = 0;
            Ok(state.faceid_confidence > 90)
        }

        pub fn get_confidence() -> u8 {
            let state = STATE.lock().unwrap();
            state.faceid_confidence
        }

        pub fn calibrate() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.faceid_enabled {
                return Err("Face recognition not enabled");
            }
            state.faceid_confidence = 98;
            Ok(())
        }
    }

    pub mod iris {
        use super::STATE;

        pub fn enable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.iris_enabled = true;
            state.iris_quality = 88;
            Ok(())
        }

        pub fn disable() -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            state.iris_enabled = false;
            state.iris_quality = 0;
            Ok(())
        }

        pub fn enroll(iris_id: u32) -> Result<(), &'static str> {
            let mut state = STATE.lock().unwrap();
            if !state.iris_enabled {
                return Err("Iris scanner not enabled");
            }
            if iris_id > 10 {
                return Err("Iris ID out of range");
            }
            state.iris_templates = iris_id + 1;
            Ok(())
        }

        pub fn verify(iris_id: u32) -> Result<bool, &'static str> {
            let state = STATE.lock().unwrap();
            if !state.iris_enabled {
                return Err("Iris scanner not enabled");
            }
            if iris_id >= state.iris_templates {
                return Err("Template not found");
            }
            Ok(true)
        }

        pub fn get_quality() -> u8 {
            let state = STATE.lock().unwrap();
            state.iris_quality
        }
    }
}

use mock_biometric as biometric;

#[test]
fn test_fingerprint_lifecycle() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::fingerprint::enable().is_ok());
    assert_eq!(biometric::fingerprint::get_status(), 0x1);
    
    assert!(biometric::fingerprint::enroll(0).is_ok());
    assert_eq!(biometric::fingerprint::get_template_count(), 1);
    
    assert!(biometric::fingerprint::verify(0).is_ok());
    assert_eq!(biometric::fingerprint::get_attempts(), 0);
    
    assert!(biometric::fingerprint::disable().is_ok());
    assert_eq!(biometric::fingerprint::get_status(), 0x0);
}

#[test]
fn test_fingerprint_enroll_multiple() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::fingerprint::enable().is_ok());
    
    for id in 0..5 {
        assert!(biometric::fingerprint::enroll(id).is_ok());
    }
    
    assert_eq!(biometric::fingerprint::get_template_count(), 5);
    assert!(biometric::fingerprint::enroll(6).is_err());
}

#[test]
fn test_fingerprint_verify_failures() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::fingerprint::enable().is_ok());
    assert!(biometric::fingerprint::enroll(0).is_ok());
    
    // Verify non-existent template
    assert!(biometric::fingerprint::verify(5).is_err());
    assert_eq!(biometric::fingerprint::get_attempts(), 1);
    
    // Verify with disabled scanner
    assert!(biometric::fingerprint::disable().is_ok());
    for _ in 0..5 {
        let _ = biometric::fingerprint::verify(0);
    }
    assert!(biometric::fingerprint::verify(0).is_err());
}

#[test]
fn test_faceid_unlock() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::faceid::enable().is_ok());
    assert_eq!(biometric::faceid::get_confidence(), 95);
    
    assert!(biometric::faceid::unlock_with_face().is_ok());
    assert!(biometric::faceid::unlock_with_face().unwrap());
}

#[test]
fn test_faceid_calibration() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::faceid::enable().is_ok());
    assert!(biometric::faceid::calibrate().is_ok());
    assert_eq!(biometric::faceid::get_confidence(), 98);
}

#[test]
fn test_faceid_lockout() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::faceid::disable().is_ok());
    
    for _ in 0..5 {
        let _ = biometric::faceid::unlock_with_face();
    }
    
    assert!(biometric::faceid::unlock_with_face().is_err());
}

#[test]
fn test_iris_lifecycle() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::iris::enable().is_ok());
    assert_eq!(biometric::iris::get_quality(), 88);
    
    assert!(biometric::iris::enroll(0).is_ok());
    assert!(biometric::iris::verify(0).is_ok());
    
    assert!(biometric::iris::disable().is_ok());
}

#[test]
fn test_iris_verify_range() {
    sim_reset();
    let mut state = mock_biometric::STATE.lock().unwrap();
    state.reset();
    drop(state);

    assert!(biometric::iris::enable().is_ok());
    
    for id in 0..3 {
        assert!(biometric::iris::enroll(id).is_ok());
    }
    
    // Verify existing templates
    for id in 0..3 {
        assert!(biometric::iris::verify(id).is_ok());
    }
    
    // Verify out-of-range template
    assert!(biometric::iris::verify(10).is_err());
}
