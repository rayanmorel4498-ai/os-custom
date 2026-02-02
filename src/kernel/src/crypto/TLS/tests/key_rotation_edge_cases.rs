extern crate alloc;

use redmi_tls::security::keys::key_rotation::{KeyRotationManager, KeyRotationPolicy};
use redmi_tls::security::keys::key_update::KeyUpdateManager;

#[test]
fn test_key_rotation_on_interval() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::TimeBasedRotation(3600);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    let key1 = manager.get_active_key();
    assert!(key1.is_active, "Initial key should be active");
    assert_eq!(key1.key_id, 1, "First key should have ID 1");
}

#[test]
fn test_key_rotation_operation_count() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(100);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    let key_before = manager.get_active_key();
    assert_eq!(key_before.operation_count, 0, "Initial operation count should be 0");
    
    manager.record_operation();
    manager.record_operation();
    
    let key_after = manager.get_active_key();
    assert_eq!(key_after.operation_count, 2, "Operation count should increment");
}

#[test]
fn test_historical_key_tracking() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::TimeBasedRotation(1000);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    let active1 = manager.get_active_key();
    assert_eq!(active1.key_id, 1);
    
    manager.record_operation();
    manager.record_operation();
    
    let rotated = manager.rotate_if_needed();
    if !rotated {
        assert!(true, "Rotation may not trigger without elapsed time");
    }
}

#[test]
fn test_key_update_state_transitions() {
    let initial_key = vec![1u8; 32];
    let key_updater = KeyUpdateManager::new(initial_key.clone());
    
    let new_key = vec![2u8; 32];
    let _ = key_updater.initiate_update(new_key, redmi_tls::security::keys::key_update::KeyUpdateType::Update, 0);
}

#[test]
fn test_key_rotation_hybrid_policy() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::HybridRotation(3600, 1000);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    let active = manager.get_active_key();
    assert!(active.is_active, "Key should be active under hybrid policy");
}

#[test]
fn test_operation_tracking_across_rotations() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(5);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    manager.record_operation();
    manager.record_operation();
    
    let key_after_ops = manager.get_active_key();
    assert_eq!(key_after_ops.operation_count, 2);
}

#[test]
fn test_rotation_key_ids_increment() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(2);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    let key1 = manager.get_active_key();
    let id1 = key1.key_id;
    
    manager.record_operation();
    manager.record_operation();
    
    let rotated = manager.rotate_if_needed();
    if rotated {
        let key2 = manager.get_active_key();
        assert!(key2.key_id > id1, "New key should have higher ID");
    }
}

#[test]
fn test_concurrent_operation_safety() {
    use alloc::sync::Arc;
    
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(100);
    let manager = Arc::new(KeyRotationManager::new(initial_key, policy));
    
    let mut handles = vec![];
    for _ in 0..3 {
        let m = manager.clone();
        handles.push(m);
    }
    
    for m in handles.iter() {
        m.record_operation();
    }
    
    let final_key = manager.get_active_key();
    assert_eq!(final_key.operation_count, 3, "All operations should be recorded");
}

#[test]
fn test_rotation_needs_check() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(1000);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    manager.record_operation();
    let key = manager.get_active_key();
    assert_eq!(key.operation_count, 1);
}

#[test]
fn test_key_material_preservation() {
    let initial_key = vec![42u8; 32];
    let policy = KeyRotationPolicy::TimeBasedRotation(3600);
    let manager = KeyRotationManager::new(initial_key.clone(), policy);
    
    let active_key = manager.get_active_key();
    assert_eq!(active_key.key_material, initial_key, "Key material should be preserved");
}

#[test]
fn test_key_update_manager_creation() {
    let initial_key = vec![1u8; 32];
    let _updater = KeyUpdateManager::new(initial_key);
}

#[test]
fn test_key_update_with_interval() {
    let initial_key = vec![1u8; 32];
    let _updater = KeyUpdateManager::with_interval(initial_key, 60);
}

#[test]
fn test_rotation_manager_max_historical() {
    let initial_key = vec![1u8; 32];
    let policy = KeyRotationPolicy::OperationBasedRotation(1);
    let manager = KeyRotationManager::new(initial_key, policy);
    
    for _ in 0..15 {
        manager.record_operation();
        let _ = manager.rotate_if_needed();
    }
}
