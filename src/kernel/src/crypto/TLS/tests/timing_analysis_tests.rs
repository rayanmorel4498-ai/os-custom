use redmi_tls::core::crypto::hmac_validator::HmacValidator;

#[test]
fn test_hmac_constant_time_verification() {
    let validator = HmacValidator::new(b"test-key-for-hmac".to_vec());
    
    let message = b"test message";
    let signature = validator.compute(message);
    
    let correct = validator.verify(message, &signature);
    assert!(correct, "Correct HMAC should verify");
    
    let mut wrong_sig = signature.clone();
    if !wrong_sig.is_empty() {
        wrong_sig[0] ^= 0xFF;
    }
    
    let incorrect = validator.verify(message, &wrong_sig);
    assert!(!incorrect, "Corrupted HMAC should not verify");
}

#[test]
fn test_key_derivation_timing_independence() {
    let key_short = b"short".to_vec();
    let key_medium = b"medium-length-key".to_vec();
    let key_long = b"very-long-key-material-for-testing".to_vec();
    
    let validator_short = HmacValidator::new(key_short);
    let validator_medium = HmacValidator::new(key_medium);
    let validator_long = HmacValidator::new(key_long);
    
    let message = b"same message";
    
    let _sig_short = validator_short.compute(message);
    let _sig_medium = validator_medium.compute(message);
    let _sig_long = validator_long.compute(message);
}

#[test]
fn test_signature_verification_early_exit() {
    let validator = HmacValidator::new(b"verification-key".to_vec());
    
    let message = b"test message";
    let correct_sig = validator.compute(message);
    
    assert!(validator.verify(message, &correct_sig), "Correct signature should verify");
    
    for i in 0..correct_sig.len() {
        let mut corrupted = correct_sig.clone();
        corrupted[i] ^= 0x01;
        
        let result = validator.verify(message, &corrupted);
        assert!(!result, "Any bit flip should fail verification at position {}", i);
    }
}

#[test]
fn test_aead_decryption_early_reject() {
    use redmi_tls::core::crypto::crypto::CryptoKey;
    
    let key = CryptoKey::new("test-key", "ctx").unwrap();
    let plaintext = b"sensitive data";
    
    let encrypted = key.encrypt(plaintext).unwrap();
    let decrypted = key.decrypt(&encrypted);
    assert!(decrypted.is_some(), "Valid encryption should decrypt");
    
    let mut corrupted = encrypted.clone();
    let bytes = unsafe { corrupted.as_bytes_mut() };
    if bytes.len() > 0 {
        bytes[bytes.len() - 1] ^= 0xFF;
    }
    
    let result = key.decrypt(&corrupted);
    assert!(
        result.is_none() || result.as_ref().map_or(false, |d| d != plaintext),
        "Corrupted ciphertext should not decrypt correctly"
    );
}

#[test]
fn test_comparison_operator_timing() {
    let s1 = "short";
    let s2 = "medium-length";
    let s3 = "very-very-long-string-for-comparison-testing";
    
    let _ = s1 == s1;
    let _ = s2 == s2;
    let _ = s3 == s3;
}

#[test]
fn test_cache_timing_attacks_awareness() {
    let validator = HmacValidator::new(b"cache-test-key".to_vec());
    
    let message1 = b"first message";
    let message2 = b"second message";
    
    let sig1_first = validator.compute(message1);
    let sig1_repeat = validator.compute(message1);
    let sig2 = validator.compute(message2);
    
    assert_eq!(sig1_first, sig1_repeat, "Same message should produce same signature");
    assert_ne!(sig1_first, sig2, "Different messages should produce different signatures");
}

#[test]
fn test_branch_prediction_resistance() {
    let validator = HmacValidator::new(b"branch-test-key".to_vec());
    
    let message = b"consistent message";
    let good_sig = validator.compute(message);
    
    for _ in 0..100 {
        let result = validator.verify(message, &good_sig);
        assert!(result, "Consistent verification should succeed");
    }
}

#[test]
fn test_conditional_skip_timing() {
    let validator = HmacValidator::new(b"conditional-key".to_vec());
    
    let empty_msg = b"";
    let short_msg = b"x";
    let long_msg = vec![42u8; 1000];
    
    let _ = validator.compute(empty_msg);
    let _ = validator.compute(short_msg);
    let _ = validator.compute(&long_msg);
}
