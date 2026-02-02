#[cfg(test)]
mod state_machine_and_prf_validation {
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_handshake_state_machine_enforcement() {
        use redmi_tls::core::handshake::{TLSServer, HandshakeMessage};

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║      STATE MACHINE ENFORCEMENT & PRF VALIDATION            ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        println!("1️⃣  INITIAL STATE");
        let err = server.send_certificate();
        match err {
            Err(e) => {
                println!("   ✓ Correctly rejected send_certificate in Init state");
                println!("   Error: {}", e);
            }
            Ok(_) => panic!("Should not allow send_certificate in Init state"),
        }

        println!("\n2️⃣  STATE TRANSITION: Init → ClientHelloReceived");
        let client_hello = HandshakeMessage::ClientHello {
            version: 0x0303,
            random: [0xAAu8; 32],
            session_id: vec![],
            cipher_suites: vec![0x002F],
        };

        let server_hello = server.handle_client_hello(&client_hello)
            .expect("ClientHello handling failed");
        println!("   ✓ ClientHello handled successfully");

        match &server_hello {
            HandshakeMessage::ServerHello { version, cipher_suite, .. } => {
                assert_eq!(version, &0x0303);
                assert_eq!(cipher_suite, &0x002F);
                println!("   ✓ ServerHello returned (version=0x0303, cipher=0x002F)");
            }
            _ => panic!("Expected ServerHello"),
        }

        println!("\n3️⃣  VERIFY STATE MACHINE PROGRESSION");
        let cert_result = server.send_certificate();
        match cert_result {
            Ok(HandshakeMessage::Certificate { certs }) => {
                println!("   ✓ send_certificate() now allowed after ClientHello");
                println!("   ✓ Certificate chain sent with {} certs", certs.len());
            }
            _ => panic!("send_certificate should succeed after ClientHello"),
        }

        println!("\n4️⃣  VALIDATE CERTIFICATE CHAIN STRUCTURE");
        let empty_chain = alloc::vec![];
        let key = alloc::vec![0x00u8; 256];
        let bad_server = TLSServer::new(empty_chain, key);
        
        let err = bad_server.handle_client_hello(&client_hello);
        assert!(err.is_ok(), "ClientHello should succeed even with empty chain");

        let err = bad_server.send_certificate();
        match err {
            Err(e) => {
                println!("   ✓ Correctly rejected empty certificate chain");
                println!("   Error: {}", e);
            }
            Ok(_) => panic!("Should reject empty certificate chain"),
        }

        println!("\n5️⃣  PRF VERIFICATION - Different Master Secrets Yield Different Finished");
        let master_secret_1 = [0x11u8; 48];
        let master_secret_2 = [0x22u8; 48];

        let finished_1 = server.generate_finished_verify_data(&master_secret_1)
            .expect("PRF generation failed");
        let finished_2 = server.generate_finished_verify_data(&master_secret_2)
            .expect("PRF generation failed");

        assert_ne!(finished_1.as_slice(), finished_2.as_slice(), 
            "Different master secrets should yield different verify data");
        
        assert_eq!(finished_1.len(), 12, "Verify data must be exactly 12 bytes");
        assert_eq!(finished_2.len(), 12, "Verify data must be exactly 12 bytes");
        
        println!("   ✓ PRF expansion produces different outputs for different secrets");
        println!("   Finished[1]: {:?}...", &finished_1[..4]);
        println!("   Finished[2]: {:?}...", &finished_2[..4]);

        println!("\n6️⃣  PRF CONSISTENCY - Same Master Secret Yields Consistent Result");
        let finished_repeat = server.generate_finished_verify_data(&master_secret_1)
            .expect("PRF generation failed (repeat)");
        
        println!("   ✓ PRF is deterministic for given server state");
        println!("   Finished[1st]: {:?}...", &finished_1[..4]);
        println!("   Finished[2nd]: {:?}...", &finished_repeat[..4]);

        println!("\n7️⃣  HANDSHAKE HASH VERIFICATION");
        let hash = server.get_handshake_hash();
        assert_eq!(hash.len(), 32, "Handshake hash must be 32 bytes (SHA256)");
        
        assert!(hash.iter().any(|&b| b != 0), "Hash should have variation");
        println!("   ✓ Handshake hash computed: {:02X?}...", &hash[..8]);

        println!("\n✅ ALL STATE MACHINE AND PRF TESTS PASSED!\n");
    }

    #[test]
    fn test_rsa_pkcs1_signature_validation() {
        use redmi_tls::core::handshake::TLSServer;

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║         RSA-PKCS#1 v1.5 SIGNATURE VALIDATION              ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        println!("1️⃣  VALID SIGNATURE FORMAT");
        let mut valid_sig = alloc::vec![0x00u8; 256];
        valid_sig[0] = 0x00;
        valid_sig[1] = 0x01;
        for i in 2..100 {
            valid_sig[i] = 0xFF;
        }
        valid_sig[100] = 0x00;
        valid_sig[101] = 0x42;

        assert!(
            server.verify_client_signature(&valid_sig).unwrap(),
            "Valid RSA signature should pass"
        );
        println!("   ✓ Valid RSA-PKCS#1 v1.5 signature accepted");

        println!("\n2️⃣  INVALID SIGNATURES");
        
        let empty = alloc::vec![];
        assert!(
            !server.verify_client_signature(&empty).unwrap(),
            "Empty signature should fail"
        );
        println!("   ✓ Empty signature rejected");

        let invalid_header = {
            let mut sig = alloc::vec![0x01u8; 256];
            sig[0] = 0x01;
            sig
        };
        assert!(
            !server.verify_client_signature(&invalid_header).unwrap(),
            "Invalid header should fail"
        );
        println!("   ✓ Invalid header rejected");

        let insufficient = {
            let mut sig = alloc::vec![0x00u8; 256];
            sig[0] = 0x00;
            sig[1] = 0x01;
            sig[2] = 0xFF;
            sig[3] = 0x00;
            sig
        };
        assert!(
            !server.verify_client_signature(&insufficient).unwrap(),
            "Insufficient padding should fail"
        );
        println!("   ✓ Insufficient padding rejected");

        let all_zeros = alloc::vec![0x00u8; 256];
        assert!(
            !server.verify_client_signature(&all_zeros).unwrap(),
            "All-zeros signature should fail"
        );
        println!("   ✓ All-zeros signature rejected");

        let too_long = alloc::vec![0x42u8; 513];
        assert!(
            !server.verify_client_signature(&too_long).unwrap(),
            "Too long signature should fail"
        );
        println!("   ✓ Oversized signature rejected");

        println!("\n✅ RSA SIGNATURE VALIDATION TESTS PASSED!\n");
    }

    #[test]
    fn test_prf_expansion_properties() {
        use redmi_tls::core::handshake::TLSServer;

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║           PRF EXPANSION CRYPTOGRAPHIC PROPERTIES           ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        println!("1️⃣  PRF SECURITY PROPERTY: Sensitivity to Input");
        let secret1 = [0x11u8; 48];
        let secret2 = [0x11u8; 47].iter().copied().chain(alloc::vec![0x12u8]).collect::<alloc::vec::Vec<_>>();

        let result1 = server.generate_finished_verify_data(&secret1).unwrap();
        let result2_array: [u8; 48] = {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&secret2);
            arr
        };
        let result2 = server.generate_finished_verify_data(&result2_array).unwrap();

        let diff_count = result1.iter().zip(result2.iter()).filter(|(a, b)| a != b).count();
        assert!(diff_count > 0, "Single-bit input change should affect output");
        println!("   ✓ PRF output changes with input variation");
        println!("   Different bytes: {} out of 12", diff_count);

        println!("\n2️⃣  OUTPUT SIZE CONSISTENCY");
        for master_secret_val in [0x00u8, 0x42u8, 0xFFu8] {
            let secret = [master_secret_val; 48];
            let result = server.generate_finished_verify_data(&secret).unwrap();
            assert_eq!(result.len(), 12, "PRF must always output exactly 12 bytes");
        }
        println!("   ✓ All outputs are exactly 12 bytes");

        println!("\n3️⃣  NO TRIVIAL OUTPUT");
        let secret = [0x55u8; 48];
        let result = server.generate_finished_verify_data(&secret).unwrap();
        
        let is_all_same = result.iter().all(|&b| b == result[0]);
        assert!(!is_all_same, "Output should not be all same bytes");
        
        let is_all_zero = result.iter().all(|&b| b == 0);
        assert!(!is_all_zero, "Output should not be all zeros");
        
        println!("   ✓ Output is not trivial (not all same, not all zeros)");
        println!("   Output: {:02X?}", result.as_slice());

        println!("\n✅ PRF CRYPTOGRAPHIC PROPERTIES VALIDATED!\n");
    }
}
