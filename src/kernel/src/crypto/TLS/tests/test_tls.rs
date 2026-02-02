use redmi_tls::core::session::session_manager::SessionManager;
use redmi_tls::core::handshake::early_data::EarlyDataManager;
use redmi_tls::api::token;

#[test]
fn test_tls_session_manager_creation() {
    let _session_mgr = SessionManager::new(
        "test-master-key-1234567890ab",
        3600,
        7200,
    );
}

#[test]
fn test_tls_session_manager_multiple_instances() {
    let _mgr1 = SessionManager::new("key1", 3600, 7200);
    let _mgr2 = SessionManager::new("key2", 3600, 7200);
}

#[test]
fn test_tls_session_manager_timeout_values() {
    let _session_mgr = SessionManager::new("test-key", 1800, 3600);
}

#[test]
fn test_tls_token_generation() {
    let master_key = "test-master-key-1234567890ab";
    let token_str = token::generate_token(master_key, "test-context", 3600)
        .expect("Token generation failed");
    assert!(!token_str.is_empty(), "Generated token should not be empty");
    assert!(token_str.len() > 10, "Token should have reasonable length");
}

#[test]
fn test_tls_token_generation_different_validity() {
    let master_key = "diff-validity-key";
    let token_short = token::generate_token(master_key, "ctx1", 60)
        .expect("Short validity token failed");
    let token_long = token::generate_token(master_key, "ctx1", 86400)
        .expect("Long validity token failed");
    assert_ne!(token_short, token_long, "Tokens with different validity should differ");
}

#[test]
fn test_tls_token_validation() {
    let master_key = "test-master-key-1234567890ab";
    let context = "test-context";
    let token_str = token::generate_token(master_key, context, 3600)
        .expect("Token generation failed");
    let is_valid = token::validate_token(master_key, context, &token_str);
    assert!(is_valid, "Generated token should be valid");
}

#[test]
fn test_tls_invalid_token_rejection() {
    let master_key = "test-master-key-1234567890ab";
    let context = "test-context";
    let invalid_token = "invalid.token.data";
    let is_valid = token::validate_token(master_key, context, invalid_token);
    assert!(!is_valid, "Invalid token should not validate");
}

#[test]
fn test_tls_token_empty_rejection() {
    let master_key = "test-master-key";
    let is_valid = token::validate_token(master_key, "ctx", "");
    assert!(!is_valid, "Empty token should not validate");
}

#[test]
fn test_tls_token_malformed_rejection() {
    let master_key = "test-key";
    let malformed_tokens = vec![
        "x",
        "invalid",
        "very.short.malformed",
        "!@#$%^&*()",
        "\0\0\0",
    ];
    for malformed in malformed_tokens {
        let is_valid = token::validate_token(master_key, "ctx", malformed);
        assert!(!is_valid, "Malformed token '{}' should not validate", malformed);
    }
}

#[test]
fn test_tls_token_wrong_master_key_rejection() {
    let master_key1 = "master-key-1-secure-long-enough";
    let master_key2 = "master-key-2-secure-long-enough";
    let token_str = token::generate_token(master_key1, "context", 3600)
        .expect("Token generation failed");
    let is_valid = token::validate_token(master_key2, "context", &token_str);
    assert!(!is_valid, "Token should not validate with wrong master key");
}

#[test]
fn test_tls_early_data_storage() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    let identity = b"test-identity".to_vec();
    let data = b"early-data-content".to_vec();
    let stored = early_data_mgr.store_early_data(identity.clone(), data);
    assert!(stored, "Early data should be stored successfully");
}

#[test]
fn test_tls_early_data_retrieval() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    let identity = b"test-identity-2".to_vec();
    let data = b"early-data-content-2".to_vec();
    early_data_mgr.store_early_data(identity.clone(), data.clone());
    let retrieved = early_data_mgr.get_early_data(&identity);
    assert!(retrieved.is_some(), "Early data should be retrievable");
    if let Some(info) = retrieved {
        assert_eq!(info.data, data, "Retrieved data should match original");
    }
}

#[test]
fn test_tls_early_data_non_existent() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    let identity = b"non-existent".to_vec();
    let retrieved = early_data_mgr.get_early_data(&identity);
    assert!(retrieved.is_none(), "Non-existent early data should return None");
}

#[test]
fn test_tls_early_data_oversized_rejection() {
    let early_data_mgr = EarlyDataManager::new(100, 3600);
    let identity = b"test-oversized".to_vec();
    let oversized_data = vec![0xFF; 200];
    let stored = early_data_mgr.store_early_data(identity, oversized_data);
    assert!(!stored, "Oversized early data should be rejected");
}

#[test]
fn test_tls_early_data_removal() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    let identity = b"test-remove".to_vec();
    let data = b"removable-data".to_vec();
    early_data_mgr.store_early_data(identity.clone(), data);
    let removed = early_data_mgr.remove_early_data(&identity);
    assert!(removed, "Early data should be removed");
    
    let retrieved = early_data_mgr.get_early_data(&identity);
    assert!(retrieved.is_none(), "Removed early data should not be retrievable");
}

#[test]
fn test_tls_early_data_remove_non_existent() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    let identity = b"non-existent-remove".to_vec();
    let removed = early_data_mgr.remove_early_data(&identity);
    assert!(!removed, "Removing non-existent early data should return false");
}

#[test]
fn test_tls_multiple_token_generation() {
    let master_key = "test-master-key";
    let context = "multi-context";
    let mut tokens = Vec::new();
    for _ in 0..5 {
        let token_str = token::generate_token(master_key, context, 3600)
            .expect("Token generation failed");
        tokens.push(token_str);
    }
    let unique_tokens: std::collections::HashSet<_> = tokens.iter().cloned().collect();
    assert_eq!(unique_tokens.len(), 5, "All tokens should be unique");
}

#[test]
fn test_tls_token_context_validation() {
    let master_key = "context-validation-key";
    let token_str = token::generate_token(master_key, "valid-context", 3600)
        .expect("Token generation failed");
    let valid_with_correct = token::validate_token(master_key, "valid-context", &token_str);
    let valid_with_wrong = token::validate_token(master_key, "wrong-context", &token_str);
    assert!(valid_with_correct, "Token should validate with correct context");
    assert!(!valid_with_wrong, "Token should not validate with wrong context");
}

#[test]
fn test_tls_multiple_early_data_instances() {
    let mgr1 = EarlyDataManager::new(8192, 1800);
    let mgr2 = EarlyDataManager::new(8192, 1800);
    
    let id1 = b"id1".to_vec();
    let data1 = b"data1".to_vec();
    let id2 = b"id2".to_vec();
    let data2 = b"data2".to_vec();
    
    mgr1.store_early_data(id1.clone(), data1.clone());
    mgr2.store_early_data(id2.clone(), data2.clone());
    
    let retrieved1 = mgr1.get_early_data(&id1);
    assert!(retrieved1.is_some(), "Manager1 should have its data");
    if let Some(info1) = retrieved1 {
        assert_eq!(info1.data, data1, "Manager1 data should match");
    }
    assert!(mgr1.get_early_data(&id2).is_none(), "Manager1 should not have Manager2's data");
}
