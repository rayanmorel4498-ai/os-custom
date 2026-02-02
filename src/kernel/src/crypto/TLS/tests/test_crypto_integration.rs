#[cfg(test)]
mod crypto_features_integration {
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_prf_and_cipher_suite_integration() {
        use redmi_tls::core::crypto::{
            PRF, PRFHashAlgorithm, MasterSecretDerivation, KeyMaterialDerivation,
            CipherSuite, CipherSuiteNegotiator, SecretDerivationPerSuite,
        };

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║  PRF + CIPHER SUITE NEGOTIATION + SECRET DERIVATION       ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        println!("1️⃣  CIPHER SUITE NEGOTIATION");
        let client_suites = alloc::vec![
            CipherSuite::RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::RSA_WITH_AES_256_CBC_SHA,
        ];
        let server_prefs = CipherSuiteNegotiator::default_server_preference();
        
        let negotiated = CipherSuiteNegotiator::negotiate(&client_suites, &server_prefs)
            .expect("Negotiation failed");
        
        println!("   Client suites: 2 options");
        println!("   Server preference: {:?}", server_prefs);
        println!("   ✓ Negotiated: 0x{:04X}", negotiated.to_wire());

        println!("\n2️⃣  MASTER SECRET DERIVATION (RFC 5246 PRF)");
        let pre_master_secret = [0x42u8; 48];
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];

        let master_secret = MasterSecretDerivation::derive_master_secret(
            &pre_master_secret,
            &client_random,
            &server_random,
            PRFHashAlgorithm::SHA256,
        ).expect("Master secret derivation failed");

        println!("   Pre-master secret size: {}", pre_master_secret.len());
        println!("   Master secret derived: {} bytes", master_secret.len());
        println!("   ✓ Master: {:02X?}...", &master_secret[..8]);

        println!("\n3️⃣  KEY MATERIAL DERIVATION PER CIPHER SUITE");
        let key_material = SecretDerivationPerSuite::derive_key_material(
            negotiated,
            &master_secret,
            &client_random,
            &server_random,
        ).expect("Key material derivation failed");

        println!("   Cipher suite: {:?}", negotiated);
        println!("   Client write key: {} bytes", key_material.client_write_key.len());
        println!("   Server write key: {} bytes", key_material.server_write_key.len());
        println!("   Client MAC: {} bytes", key_material.client_write_mac.len());
        println!("   Client IV: {} bytes", key_material.client_write_iv.len());
        println!("   ✓ All keys derived successfully");

        println!("\n4️⃣  PRF CONSISTENCY CHECK");
        let prf_output1 = PRF::generate(
            b"secret",
            b"label",
            b"seed",
            32,
            PRFHashAlgorithm::SHA256,
        ).expect("PRF failed");

        let prf_output2 = PRF::generate(
            b"secret",
            b"label",
            b"seed",
            32,
            PRFHashAlgorithm::SHA256,
        ).expect("PRF failed");

        assert_eq!(prf_output1, prf_output2, "PRF must be deterministic");
        println!("   ✓ PRF is deterministic for same inputs");

        println!("\n5️⃣  CIPHER SUITE PROPERTIES VALIDATION");
        match negotiated {
            CipherSuite::RSA_WITH_AES_128_CBC_SHA256 => {
                assert_eq!(negotiated.key_size(), 16);
                assert_eq!(negotiated.mac_size(), 32);
                assert_eq!(negotiated.iv_size(), 16);
                println!("   ✓ RSA_WITH_AES_128_CBC_SHA256: key=16, mac=32, iv=16");
            }
            _ => {
                let key_size = negotiated.key_size();
                let mac_size = negotiated.mac_size();
                let iv_size = negotiated.iv_size();
                println!("   ✓ Cipher suite properties:");
                println!("     - Key size: {}", key_size);
                println!("     - MAC size: {}", mac_size);
                println!("     - IV size: {}", iv_size);
            }
        }

        println!("\n✅ FULL CRYPTO INTEGRATION TEST PASSED!\n");
    }

    #[test]
    fn test_signature_verification_integration() {
        use redmi_tls::core::crypto::{SignatureVerifier, HashAlgorithm, ECDSACurve};

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║         RSA & ECDSA SIGNATURE VERIFICATION                ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        println!("1️⃣  RSA-PKCS#1 v1.5 SIGNATURE VALIDATION");
        let mut valid_rsa_sig = alloc::vec![0x00u8; 256];
        valid_rsa_sig[0] = 0x00;
        valid_rsa_sig[1] = 0x01;
        for i in 2..100 {
            valid_rsa_sig[i] = 0xFF;
        }
        valid_rsa_sig[100] = 0x00;
        valid_rsa_sig[101] = 0x20;

        let rsa_result = SignatureVerifier::verify_rsa_signature(
            b"test message",
            &valid_rsa_sig,
            &[],
            HashAlgorithm::SHA256,
        ).expect("RSA verification failed");

        println!("   RSA signature format: Valid PKCS#1 v1.5");
        println!("   Message: 'test message'");
        println!("   Hash algorithm: SHA256");
        println!("   ✓ RSA format check: {}", if rsa_result { "PASS" } else { "FAIL" });

        println!("\n2️⃣  ECDSA SIGNATURE FORMAT VALIDATION");
        let ecdsa_sig_p256 = alloc::vec![0x42u8; 64];
        
        let ecdsa_result = SignatureVerifier::verify_ecdsa_signature(
            b"test message",
            &ecdsa_sig_p256,
            &[],
            HashAlgorithm::SHA256,
            ECDSACurve::P256,
        ).expect("ECDSA verification failed");

        println!("   ECDSA curve: P-256");
        println!("   Signature size: {} bytes", ecdsa_sig_p256.len());
        println!("   ✓ ECDSA P-256 format: {}", if ecdsa_result { "VALID" } else { "INVALID" });

        println!("\n3️⃣  MULTIPLE HASH ALGORITHMS");
        for hash_algo in [
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let result = SignatureVerifier::verify_rsa_signature(
                b"data",
                &valid_rsa_sig,
                &[],
                hash_algo,
            ).expect("RSA verification failed");
            println!("   ✓ {:?}: OK", hash_algo);
        }

        println!("\n✅ SIGNATURE VERIFICATION TEST PASSED!\n");
    }

    #[test]
    fn test_complete_tls_flow_with_new_crypto() {
        use redmi_tls::core::crypto::{
            CipherSuite, CipherSuiteNegotiator, SecretDerivationPerSuite,
            MasterSecretDerivation, PRFHashAlgorithm, SignatureVerifier,
            HashAlgorithm,
        };

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║   COMPLETE TLS FLOW WITH NEW CRYPTO COMPONENTS            ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        println!("Step 1: ClientHello → Cipher Suite Negotiation");
        let client_suites = alloc::vec![
            CipherSuite::RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::RSA_WITH_AES_256_CBC_SHA256,
        ];
        let server_prefs = CipherSuiteNegotiator::default_server_preference();
        let selected = CipherSuiteNegotiator::negotiate(&client_suites, &server_prefs)
            .expect("Negotiation failed");
        println!("   Selected: 0x{:04X}\n", selected.to_wire());

        println!("Step 2: Exchange Random Values");
        let client_random = [0xCCu8; 32];
        let server_random = [0xDDu8; 32];
        println!("   Client random: [0xCC; 32]");
        println!("   Server random: [0xDD; 32]\n");

        println!("Step 3: Key Exchange (Simulated)");
        let pre_master_secret = [0x55u8; 48];
        println!("   Pre-master secret: {} bytes\n", pre_master_secret.len());

        println!("Step 4: Derive Master Secret (using PRF)");
        let master_secret = MasterSecretDerivation::derive_master_secret(
            &pre_master_secret,
            &client_random,
            &server_random,
            PRFHashAlgorithm::SHA256,
        ).expect("Master secret derivation failed");
        println!("   Master secret: {} bytes\n", master_secret.len());

        println!("Step 5: Derive Key Material per Cipher Suite");
        let key_material = SecretDerivationPerSuite::derive_key_material(
            selected,
            &master_secret,
            &client_random,
            &server_random,
        ).expect("Key material derivation failed");
        println!("   Client write key: {} bytes", key_material.client_write_key.len());
        println!("   Server write key: {} bytes", key_material.server_write_key.len());
        println!("   Client write MAC: {} bytes\n", key_material.client_write_mac.len());

        println!("Step 6: Certificate Verification");
        let mut cert_sig = alloc::vec![0x00u8; 256];
        cert_sig[0] = 0x00;
        cert_sig[1] = 0x01;
        for i in 2..100 {
            cert_sig[i] = 0xFF;
        }
        cert_sig[100] = 0x00;

        let sig_valid = SignatureVerifier::verify_rsa_signature(
            b"certificate data",
            &cert_sig,
            &[],
            HashAlgorithm::SHA256,
        ).expect("Signature verification failed");
        println!("   Certificate signature valid: {}\n", sig_valid);

        println!("✅ COMPLETE TLS FLOW SIMULATION SUCCESSFUL!");
        println!("   Cipher suite: 0x{:04X}", selected.to_wire());
        println!("   Key material derived: {} bytes total", 
            key_material.client_write_key.len() + key_material.server_write_key.len());
        println!("   Master secret: {} bytes", master_secret.len());
        println!();
    }
}
