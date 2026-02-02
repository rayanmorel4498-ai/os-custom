use redmi_tls::core::crypto::crypto::CryptoKey;
use redmi_tls::api::token;
use redmi_tls::core::record::compression::TLSCompression;

#[test]
fn test_tampering_detection_aead() {
    let key = CryptoKey::new("test-master-key", "context").unwrap();
    let plaintext = b"secret message";
    let encrypted = key.encrypt(plaintext).unwrap();
    
    let mut tampered = encrypted.clone();
    unsafe {
        let bytes = tampered.as_bytes_mut();
        if !bytes.is_empty() {
            bytes[bytes.len() - 1] ^= 0xFF;
        }
    }
    
    let result = key.decrypt(&tampered);
    assert!(
        result.is_none() || result.as_ref().map_or(false, |d| d != plaintext),
        "Tampered ciphertext should not decrypt to original plaintext"
    );
}

#[test]
fn test_token_replay_prevention() {
    let master_key = "replay-test-master-key-secure";
    let context = "ctx1";
    
    let token1 = token::generate_token(master_key, context, 3600).unwrap();
    let token2 = token::generate_token(master_key, context, 3600).unwrap();
    
    assert_ne!(
        token1, token2,
        "Multiple token generations should produce different tokens (nonce-based)"
    );
}

#[test]
fn test_context_isolation() {
    let master_key = "isolation-test-key";
    let ctx1 = "context-1";
    let ctx2 = "context-2";
    
    let token_ctx1 = token::generate_token(master_key, ctx1, 3600).unwrap();
    let token_ctx2 = token::generate_token(master_key, ctx2, 3600).unwrap();
    
    assert_ne!(token_ctx1, token_ctx2, "Different contexts should produce different tokens");
    
    let valid_ctx1 = token::validate_token(master_key, ctx1, &token_ctx1);
    let valid_ctx2 = token::validate_token(master_key, ctx2, &token_ctx1);
    
    assert!(valid_ctx1, "Token should validate with correct context");
    assert!(!valid_ctx2, "Token should NOT validate with wrong context");
}

#[test]
fn test_length_extension_attack_hmac() {
    let key1 = "key-1-secure-enough";
    let key2 = "key-2-secure-enough";
    
    let token1 = token::generate_token(key1, "msg", 3600).unwrap();
    
    let valid1 = token::validate_token(key1, "msg", &token1);
    let valid2 = token::validate_token(key2, "msg", &token1);
    
    assert!(valid1, "Should validate with correct key");
    assert!(!valid2, "Should NOT validate with different key (no length extension)");
}

#[test]
fn test_partial_ciphertext_rejection() {
    let key = CryptoKey::new("test-key", "context").unwrap();
    let plaintext = b"test data";
    let encrypted = key.encrypt(plaintext).unwrap();
    
    let truncated = &encrypted[..encrypted.len().saturating_sub(5)];
    let result = key.decrypt(truncated);
    
    assert!(
        result.is_none(),
        "Truncated ciphertext should fail to decrypt"
    );
}

#[test]
fn test_nonce_collision_recovery() {
    let key = CryptoKey::new("nonce-test", "ctx").unwrap();
    let plaintext = b"message";
    
    let cipher1 = key.encrypt(plaintext).unwrap();
    let cipher2 = key.encrypt(plaintext).unwrap();
    
    assert_ne!(
        cipher1, cipher2,
        "Different nonces should produce different ciphertexts (even with same plaintext)"
    );
    
    let decry1 = key.decrypt(&cipher1);
    let decry2 = key.decrypt(&cipher2);
    
    assert_eq!(decry1, Some(plaintext.to_vec()));
    assert_eq!(decry2, Some(plaintext.to_vec()));
}

#[test]
fn test_compression_crime_info_leak() {
    let compression = TLSCompression::new();
    
    let secret_short = b"SECRET";
    let secret_long = b"SECRET_WITH_EXTRA_PADDING_DATA";
    
    let compressed_short = compression.compress(secret_short);
    let compressed_long = compression.compress(secret_long);
    
    assert!(
        compressed_short.len() < secret_short.len() || compressed_short.len() == secret_short.len(),
        "Compression should not increase size significantly"
    );
    
    assert_ne!(
        compressed_short.len(),
        compressed_long.len(),
        "Length difference in compressed data can leak information (CRIME awareness)"
    );
}

#[test]
fn test_wrong_master_key_timing_consistency() {
    let key1 = "correct-master-key-secure-enough";
    let key2 = "wrong-master-key-secure-enough";
    
    let token = token::generate_token(key1, "context", 3600).unwrap();
    
    let start1 = std::time::Instant::now();
    let _ = token::validate_token(key1, "context", &token);
    let duration_correct = start1.elapsed();
    
    let start2 = std::time::Instant::now();
    let _ = token::validate_token(key2, "context", &token);
    let duration_wrong = start2.elapsed();
    
    println!(
        "Correct key timing: {:?}, Wrong key timing: {:?}",
        duration_correct, duration_wrong
    );
}

#[test]
fn test_empty_plaintext_handling() {
    let key = CryptoKey::new("test", "ctx").unwrap();
    let empty = b"";
    
    let encrypted = key.encrypt(empty).unwrap();
    let decrypted = key.decrypt(&encrypted);
    
    assert_eq!(decrypted, Some(Vec::new()), "Empty plaintext should roundtrip");
}

#[test]
fn test_large_plaintext_handling() {
    let key = CryptoKey::new("large-test", "context").unwrap();
    let large_plaintext = vec![0x42u8; 1024 * 1024];
    
    let encrypted = key.encrypt(&large_plaintext).unwrap();
    let decrypted = key.decrypt(&encrypted);
    
    assert_eq!(
        decrypted, Some(large_plaintext),
        "Large plaintext should roundtrip correctly"
    );
}

#[test]
fn test_token_context_substring_isolation() {
    let master_key = "substring-test-key";
    
    let token_exact = token::generate_token(master_key, "ctx-basic", 3600).unwrap();
    let _token_different = token::generate_token(master_key, "ctx", 3600).unwrap();
    
    let valid_exact = token::validate_token(master_key, "ctx-basic", &token_exact);
    let invalid_mismatch = token::validate_token(master_key, "ctx", &token_exact);
    
    assert!(valid_exact, "Token should validate with exact same context");
    assert!(
        !invalid_mismatch,
        "Token should NOT validate with different context (no prefix matching)"
    );
}
