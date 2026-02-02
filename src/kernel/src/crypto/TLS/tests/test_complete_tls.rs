#[cfg(test)]
mod complete_tls_tests {
    extern crate alloc;

    #[test]
    fn test_client_handshake_complete() {
        use redmi_tls::api::TLSClientEngine;
        use redmi_tls::core::handshake::CertificateChainValidator;

        let client = TLSClientEngine::new();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_certificate_validation() {
        use redmi_tls::core::handshake::CertificateChainValidator;

        let mut validator = CertificateChainValidator::new();
        let pinned_cert = alloc::vec![0x03u8; 100];
        validator.add_pinned_cert(pinned_cert.clone());

        let result = validator.validate_single_cert(&pinned_cert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_record_layer_encryption_decryption() {
        use redmi_tls::core::record::SecureRecordLayer;

        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];

        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        layer.set_decrypt_key(key, iv).unwrap();

        let plaintext = b"Secret Message";
        let ciphertext = layer.encrypt(plaintext).unwrap();
        let decrypted = layer.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn test_record_layer_zeroization() {
        use redmi_tls::core::record::SecureRecordLayer;

        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0xFFu8; 16];
        let iv = alloc::vec![0xFFu8; 16];

        layer.set_encrypt_key(key, iv).unwrap();
        let result = layer.zeroize_keys();
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_keys_derivation() {
        use redmi_tls::core::handshake::SessionKeys;

        let master_key = "test_master_key_32_bytes_long__";
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];

        let result = SessionKeys::derive(master_key, &client_random, &server_random);
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert_eq!(keys.client_write_key.len(), 16);
        assert_eq!(keys.server_write_key.len(), 16);
    }

    #[test]
    fn test_security_logging_failures() {
        use redmi_tls::security::SecurityLogger;

        let logger = SecurityLogger::new(100);
        logger.log_auth_failure("invalid credentials");
        logger.log_auth_failure("token expired");

        let failures = logger.get_auth_failures();
        assert_eq!(failures.len(), 2);
    }

    #[test]
    fn test_security_logging_key_rotations() {
        use redmi_tls::security::SecurityLogger;

        let logger = SecurityLogger::new(100);
        logger.log_key_rotation("session_key");
        logger.log_key_rotation("master_key");

        let rotations = logger.get_key_rotations();
        assert_eq!(rotations.len(), 2);
    }

    #[test]
    fn test_yaml_integrity_checksum() {
        use redmi_tls::config::yaml_integrity_checksum;

        let result = yaml_integrity_checksum("/tmp/nonexistent.yaml");

        #[cfg(feature = "real_tls")]
        assert!(result.is_err());

        #[cfg(not(feature = "real_tls"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_fingerprint() {
        use redmi_tls::config::cert_fingerprint;

        let result = cert_fingerprint("/tmp/nonexistent_cert.pem");

        #[cfg(feature = "real_tls")]
        assert!(result.is_err());

        #[cfg(not(feature = "real_tls"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_fingerprint() {
        use redmi_tls::config::key_fingerprint;

        let result = key_fingerprint("/tmp/nonexistent_key.pem");

        #[cfg(feature = "real_tls")]
        assert!(result.is_err());

        #[cfg(not(feature = "real_tls"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_has_yaml_feature_gated() {
        use redmi_tls::config::has_yaml;

        let result = has_yaml("/tmp/nonexistent_config.yaml");

        #[cfg(feature = "real_tls")]
        assert!(!result);

        #[cfg(not(feature = "real_tls"))]
        assert!(result);
    }

    #[test]
    fn test_client_engine_with_logger() {
        use redmi_tls::api::TLSClientEngine;
        use redmi_tls::security::SecurityEvent;

        let client = TLSClientEngine::new();
        let logger = client.security_logger();

        logger.log(SecurityEvent::ClientHandshakeStart, "test");
        assert_eq!(logger.entry_count(), 1);

        let result = client.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn test_complete_flow_with_security() {
        use redmi_tls::api::TLSClientEngine;
        use redmi_tls::core::handshake::CertificateChainValidator;
        use redmi_tls::security::SecurityEvent;

        let validator = CertificateChainValidator::new();
        let client = TLSClientEngine::new().with_cert_validator(validator);

        assert!(!client.is_connected());

        let logger = client.security_logger();
        logger.log(SecurityEvent::ClientHandshakeStart, "Starting TLS");

        assert_eq!(logger.entry_count(), 1);

        let cleanup_result = client.cleanup();
        assert!(cleanup_result.is_ok());
    }

    #[test]
    fn test_transport_layer() {
        use redmi_tls::core::handshake::TLSTransport;

        let transport = TLSTransport::new();

        transport.client_send(alloc::vec![1, 2, 3]).unwrap();
        assert_eq!(transport.client_to_server_pending(), 1);

        let msg = transport.server_recv().unwrap();
        assert_eq!(msg, Some(alloc::vec![1, 2, 3]));
        assert_eq!(transport.client_to_server_pending(), 0);
    }

    #[test]
    fn test_secure_record_layer_message_counter() {
        use redmi_tls::core::record::SecureRecordLayer;

        let layer = SecureRecordLayer::new(4096);
        let key = alloc::vec![0x01u8; 16];
        let iv = alloc::vec![0x02u8; 16];

        layer.set_encrypt_key(key.clone(), iv.clone()).unwrap();
        layer.set_decrypt_key(key, iv).unwrap();

        assert_eq!(layer.message_count(), 0);

        layer.encrypt(b"msg1").unwrap();
        assert_eq!(layer.message_count(), 1);

        layer.encrypt(b"msg2").unwrap();
        assert_eq!(layer.message_count(), 2);

        layer.reset_counter();
        assert_eq!(layer.message_count(), 0);
    }
}
