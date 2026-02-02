use redmi_tls::api::token;

#[test]
fn test_tokens_basic_generation() {
    let master_key = "test-key-for-tokens";
    let token_str = token::generate_token(master_key, "test-context", 3600)
        .expect("Failed to generate token");
    
    assert!(!token_str.is_empty(), "Generated token should not be empty");
    assert!(token_str.len() > 10, "Token should have reasonable length");
}

#[test]
fn test_tokens_generation_format() {
    let master_key = "format-key-secure-long-enough";
    let token_str = token::generate_token(master_key, "format-context", 3600)
        .expect("Failed to generate token");
    
    assert!(token_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'),
        "Token should contain only alphanumeric and separators");
}

#[test]
fn test_tokens_validation_success() {
    let master_key = "test-key-validation";
    let context = "context-test";
    let token_str = token::generate_token(master_key, context, 3600)
        .expect("Failed to generate token");
    
    let is_valid = token::validate_token(master_key, context, &token_str);
    assert!(is_valid, "Generated token should be valid");
}

#[test]
fn test_tokens_invalid_token_rejection() {
    let master_key = "test-key-reject";
    let context = "test-context";
    let invalid_token = "invalid_token_data_xyz_wrong";
    
    let is_valid = token::validate_token(master_key, context, invalid_token);
    assert!(!is_valid, "Invalid token should not validate");
}

#[test]
fn test_tokens_multiple_token_independence() {
    let master_key = "multi-token-key";
    
    let token1 = token::generate_token(master_key, "context1", 3600)
        .expect("Failed to generate token 1");
    let token2 = token::generate_token(master_key, "context2", 3600)
        .expect("Failed to generate token 2");
    
    assert_ne!(token1, token2, "Different tokens should not be identical");
    
    let valid1 = token::validate_token(master_key, "context1", &token1);
    let valid2 = token::validate_token(master_key, "context2", &token2);
    
    assert!(valid1 && valid2, "Both tokens should be independently valid");
}

#[test]
fn test_tokens_context_specific_validation() {
    let master_key = "context-specific-key";
    let context_a = "context-a";
    let context_b = "context-b";
    
    let token_a = token::generate_token(master_key, context_a, 3600)
        .expect("Failed to generate token");
    
    let valid_with_correct = token::validate_token(master_key, context_a, &token_a);
    let valid_with_wrong = token::validate_token(master_key, context_b, &token_a);
    
    assert!(valid_with_correct, "Token should validate with correct context");
    assert!(!valid_with_wrong, "Token should not validate with wrong context");
}

#[test]
fn test_tokens_context_case_sensitivity() {
    let master_key = "case-key-secure-long-enough";
    let token = token::generate_token(master_key, "Context", 3600)
        .expect("Failed to generate token");
    
    let valid_exact = token::validate_token(master_key, "Context", &token);
    let valid_lower = token::validate_token(master_key, "context", &token);
    let valid_upper = token::validate_token(master_key, "CONTEXT", &token);
    
    assert!(valid_exact, "Token should validate with exact context");
    assert!(!valid_lower, "Token should not validate with different case");
    assert!(!valid_upper, "Token should not validate with different case");
}

#[test]
fn test_tokens_different_master_keys() {
    let master_key_1 = "master-key-1-secure-long-enough";
    let master_key_2 = "master-key-2-secure-long-enough";
    let context = "shared-context";
    
    let token = token::generate_token(master_key_1, context, 3600)
        .expect("Failed to generate token");
    
    let valid_with_correct = token::validate_token(master_key_1, context, &token);
    let valid_with_wrong = token::validate_token(master_key_2, context, &token);
    
    assert!(valid_with_correct, "Token should validate with correct key");
    assert!(!valid_with_wrong, "Token should not validate with different key");
}

#[test]
fn test_tokens_empty_token_rejection() {
    let master_key = "test-key";
    let context = "test-context";
    let empty_token = "";
    
    let is_valid = token::validate_token(master_key, context, empty_token);
    assert!(!is_valid, "Empty token should not validate");
}

#[test]
fn test_tokens_whitespace_rejection() {
    let master_key = "test-key";
    let context = "test-context";
    
    let whitespace_tokens = vec![" ", "\t", "\n", "  \t  ", "\r\n"];
    for ws_token in whitespace_tokens {
        let is_valid = token::validate_token(master_key, context, ws_token);
        assert!(!is_valid, "Whitespace-only token should not validate");
    }
}

#[test]
fn test_tokens_malformed_token_rejection() {
    let master_key = "test-key";
    let context = "test-context";
    let malformed_tokens = vec![
        "not_a_valid_base64!@#$%",
        "short",
        "!!!invalid!!!",
        "\0\0\0",
        "token\nwith\nnewlines",
        "token\twith\ttabs",
    ];
    
    for malformed in malformed_tokens {
        let is_valid = token::validate_token(master_key, context, malformed);
        assert!(!is_valid, "Malformed token should not validate: {}", malformed);
    }
    
    let long_token = &"x".repeat(1000);
    let is_valid = token::validate_token(master_key, context, long_token);
    assert!(!is_valid, "Extremely long token should not validate");
}

#[test]
fn test_tokens_special_characters_rejection() {
    let master_key = "test-key";
    let context = "test-context";
    
    let special_tokens = vec![
        "token<script>alert(1)</script>",
        "token';DROP TABLE;--",
        "token\x00null",
        "token|command|injection",
    ];
    
    for special in special_tokens {
        let is_valid = token::validate_token(master_key, context, special);
        assert!(!is_valid, "Special character token should not validate: {}", special);
    }
}

#[test]
fn test_tokens_rapid_generation_sequence() {
    let master_key = "rapid-gen-key-secure-long-enough";
    let mut tokens = Vec::new();
    
    for i in 0..10 {
        let context = format!("context-{}", i);
        let token_str = token::generate_token(master_key, &context, 3600)
            .expect("Failed to generate token");
        tokens.push(token_str);
    }
    
    assert_eq!(tokens.len(), 10, "Should generate 10 tokens");
    
    let all_unique = tokens.iter().collect::<std::collections::HashSet<_>>().len() == 10;
    assert!(all_unique, "All 10 tokens should be unique");
}

#[test]
fn test_tokens_token_lifetime_validity() {
    let master_key = "lifetime-test-key";
    let context = "lifetime-context";
    
    let token_long = token::generate_token(master_key, context, 86400)
        .expect("Failed to generate long-lived token");
    let token_short = token::generate_token(master_key, context, 1)
        .expect("Failed to generate short-lived token");
    
    let valid_long = token::validate_token(master_key, context, &token_long);
    let valid_short = token::validate_token(master_key, context, &token_short);
    
    assert!(valid_long, "Long-lived token should be valid immediately");
    assert!(valid_short, "Short-lived token should be valid immediately");
    assert_ne!(token_long, token_short, "Tokens should be different");
}

#[test]
fn test_tokens_different_lifetimes_generate_different_tokens() {
    let master_key = "lifetime-key-secure-long-enough";
    let context = "ctx";
    
    let mut tokens_by_lifetime = std::collections::HashMap::new();
    for lifetime in &[60, 300, 3600, 86400] {
        let token = token::generate_token(master_key, context, *lifetime)
            .expect("Failed to generate token");
        tokens_by_lifetime.insert(*lifetime, token);
    }
    
    let all_unique = tokens_by_lifetime.len() == 4 &&
        tokens_by_lifetime.values().collect::<std::collections::HashSet<_>>().len() == 4;
    assert!(all_unique, "Different lifetimes should produce different tokens");
}

#[test]
fn test_tokens_concurrent_contexts() {
    let master_key = "concurrent-key";
    let contexts = vec!["api", "database", "cache", "session", "auth"];
    
    let mut tokens = Vec::new();
    for ctx in &contexts {
        let token = token::generate_token(master_key, ctx, 3600)
            .expect("Failed to generate token");
        tokens.push((ctx.to_string(), token));
    }
    
    for (ctx, token_str) in tokens {
        let is_valid = token::validate_token(master_key, &ctx, &token_str);
        assert!(is_valid, "Token for context {} should be valid", ctx);
    }
}

#[test]
fn test_tokens_cross_context_rejection() {
    let master_key = "cross-key-secure-long-enough";
    let contexts = vec!["api", "db", "cache"];
    
    let tokens: Vec<_> = contexts.iter()
        .map(|ctx| (ctx.to_string(), 
            token::generate_token(master_key, ctx, 3600).expect("Token gen failed")))
        .collect();
    
    for (ctx, token) in &tokens {
        for other_ctx in &contexts {
            if other_ctx != ctx {
                let is_valid = token::validate_token(master_key, other_ctx, token);
                assert!(!is_valid, "Token from {} should not validate for {}", ctx, other_ctx);
            }
        }
    }
}

#[test]
fn test_tokens_generation_error_handling() {
    let master_key = "error-test-key";
    
    for _ in 0..20 {
        let token = token::generate_token(master_key, "ctx", 3600);
        assert!(token.is_ok(), "Token generation should succeed");
    }
}

#[test]
fn test_tokens_validation_error_handling() {
    let master_key = "error-validation-key";
    
    let token_str = token::generate_token(master_key, "ctx", 3600)
        .expect("Failed to generate token");
    
    for _ in 0..20 {
        let is_valid = token::validate_token(master_key, "ctx", &token_str);
        assert!(is_valid, "Token validation should consistently succeed");
    }
}
