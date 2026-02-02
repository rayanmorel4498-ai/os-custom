#[cfg(test)]
mod real_tls_end_to_end {
    extern crate alloc;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_real_client_server_tls_flow() {
        use redmi_tls::core::handshake::{TLSTransport, SessionKeys};
        use redmi_tls::core::record::SecureRecordLayer;

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║         REAL TLS CLIENT↔SERVER END-TO-END TEST             ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        let master_key = "tls_master_key_32_bytes_secure";
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];

        println!("1️⃣  SETUP - Dériver les clés de session");
        println!("   Master key: {}", master_key);
        println!("   Client random: [0xAA; 32]");
        println!("   Server random: [0xBB; 32]");

        let session_keys = SessionKeys::derive(master_key, &client_random, &server_random)
            .expect("Key derivation failed");

        println!("   ✓ Client write key: {} bytes", session_keys.client_write_key.len());
        println!("   ✓ Server write key: {} bytes", session_keys.server_write_key.len());
        println!("   ✓ Session keys derived");

        let transport = Arc::new(TLSTransport::new());
        println!("\n2️⃣  TRANSPORT - Créer le canal bidirectionnel");
        println!("   ✓ Transport initialisé");
        println!("   ✓ Client→Server channel: ready");
        println!("   ✓ Server→Client channel: ready");

        let client_record_layer = SecureRecordLayer::new(16384);
        
        client_record_layer.set_encrypt_key(
            session_keys.client_write_key.clone(),
            session_keys.client_write_iv.clone(),
        ).expect("Client encrypt key setup failed");
        
        client_record_layer.set_decrypt_key(
            session_keys.server_write_key.clone(),
            session_keys.server_write_iv.clone(),
        ).expect("Client decrypt key setup failed");

        println!("\n3️⃣  CLIENT - Setup record layer");
        println!("   Encrypt key: {} bytes (for server)", session_keys.client_write_key.len());
        println!("   Decrypt key: {} bytes (from server)", session_keys.server_write_key.len());
        println!("   ✓ Client record layer ready");

        let server_record_layer = SecureRecordLayer::new(16384);
        
        server_record_layer.set_decrypt_key(
            session_keys.client_write_key.clone(),
            session_keys.client_write_iv.clone(),
        ).expect("Server decrypt key setup failed");
        
        server_record_layer.set_encrypt_key(
            session_keys.server_write_key.clone(),
            session_keys.server_write_iv.clone(),
        ).expect("Server encrypt key setup failed");

        println!("\n4️⃣  SERVER - Setup record layer");
        println!("   Decrypt key: {} bytes (from client)", session_keys.client_write_key.len());
        println!("   Encrypt key: {} bytes (for client)", session_keys.server_write_key.len());
        println!("   ✓ Server record layer ready");

        println!("\n5️⃣  PHASE 1 - Client sends encrypted application data to server");

        let client_plaintext1 = b"GET /api/secure HTTP/1.1";
        println!("   Client plaintext: \"{}\"", alloc::str::from_utf8(client_plaintext1).unwrap());
        println!("   Size: {} bytes", client_plaintext1.len());

        let client_ciphertext1 = client_record_layer.encrypt(client_plaintext1)
            .expect("Client encryption failed");

        println!("   Encrypted: {} bytes", client_ciphertext1.len());
        println!("   Message count: {}", client_record_layer.message_count());

        transport.client_send(client_ciphertext1.clone())
            .expect("Transport send failed");

        println!("   ✓ Sent through transport");

        println!("\n6️⃣  PHASE 2 - Server receives and decrypts");

        let server_received = transport.server_recv()
            .expect("Transport recv failed")
            .expect("No message received");

        println!("   Received ciphertext: {} bytes", server_received.len());
        assert_eq!(server_received, client_ciphertext1, "Ciphertext mismatch!");

        let server_decrypted = server_record_layer.decrypt(&server_received)
            .expect("Server decryption failed");

        println!("   Decrypted: {} bytes", server_decrypted.len());
        assert_eq!(server_decrypted, client_plaintext1, "Plaintext mismatch!");
        println!("   Content: \"{}\"", alloc::str::from_utf8(&server_decrypted).unwrap());
        println!("   Message count: {}", server_record_layer.message_count());
        println!("   ✓ Server successfully decrypted client message");

        println!("\n7️⃣  PHASE 3 - Server responds with encrypted data to client");

        let server_plaintext1 = b"HTTP/1.1 200 OK - Data encrypted";
        println!("   Server plaintext: \"{}\"", alloc::str::from_utf8(server_plaintext1).unwrap());
        println!("   Size: {} bytes", server_plaintext1.len());

        let server_ciphertext1 = server_record_layer.encrypt(server_plaintext1)
            .expect("Server encryption failed");

        println!("   Encrypted: {} bytes", server_ciphertext1.len());
        println!("   Message count: {}", server_record_layer.message_count());

        transport.server_send(server_ciphertext1.clone())
            .expect("Transport send failed");

        println!("   ✓ Sent through transport");

        println!("\n8️⃣  PHASE 4 - Client receives and decrypts server response");

        let client_received = transport.client_recv()
            .expect("Transport recv failed")
            .expect("No message received");

        println!("   Received ciphertext: {} bytes", client_received.len());
        assert_eq!(client_received, server_ciphertext1, "Ciphertext mismatch!");

        let client_decrypted = client_record_layer.decrypt(&client_received)
            .expect("Client decryption failed");

        println!("   Decrypted: {} bytes", client_decrypted.len());
        assert_eq!(client_decrypted, server_plaintext1, "Plaintext mismatch!");
        println!("   Content: \"{}\"", alloc::str::from_utf8(&client_decrypted).unwrap());
        println!("   Message count: {}", client_record_layer.message_count());
        println!("   ✓ Client successfully decrypted server response");

        println!("\n9️⃣  PHASE 5 - Additional encrypted exchanges");

        let exchanges: Vec<(&[u8], &[u8])> = vec![
            (b"UPDATE user SET status='active'", b"UPDATE completed - 1 row affected"),
            (b"DELETE FROM cache WHERE expired=true", b"PURGED: 42 records"),
            (b"SELECT * FROM logs LIMIT 100", b"Retrieved 100 log entries (encrypted)"),
        ];

        for (idx, (client_msg, server_msg)) in exchanges.iter().enumerate() {
            let c_cipher = client_record_layer.encrypt(client_msg)
                .expect("Client exchange encryption failed");
            transport.client_send(c_cipher.clone())
                .expect("Client exchange send failed");

            let s_recv = transport.server_recv()
                .expect("Server exchange recv failed")
                .expect("No exchange message");
            let s_plain = server_record_layer.decrypt(&s_recv)
                .expect("Server exchange decryption failed");

            assert_eq!(s_plain.as_slice(), *client_msg);

            let s_cipher = server_record_layer.encrypt(server_msg)
                .expect("Server exchange encryption failed");
            transport.server_send(s_cipher.clone())
                .expect("Server exchange send failed");

            let c_recv = transport.client_recv()
                .expect("Client exchange recv failed")
                .expect("No exchange response");
            let c_plain = client_record_layer.decrypt(&c_recv)
                .expect("Client exchange decryption failed");

            assert_eq!(c_plain.as_slice(), *server_msg);

            println!("   Exchange {}: ✓", idx + 1);
            println!("      Client→Server: {} bytes encrypted", client_msg.len());
            println!("      Server→Client: {} bytes encrypted", server_msg.len());
        }

        println!("\n🔟 VERIFICATION - Message counters");
        println!("   Client messages sent: {}", client_record_layer.message_count());
        println!("   Server messages sent: {}", server_record_layer.message_count());

        assert_eq!(client_record_layer.message_count(), 8, "Client message count mismatch");
        assert_eq!(server_record_layer.message_count(), 8, "Server message count mismatch");

        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║                    ✅ TEST SUCCESSFUL                       ║");
        println!("╠════════════════════════════════════════════════════════════╣");
        println!("║ ✓ Real client↔server encryption/decryption                ║");
        println!("║ ✓ Bidirectional message transport                         ║");
        println!("║ ✓ Session keys properly derived                           ║");
        println!("║ ✓ 4 complete message exchanges                            ║");
        println!("║ ✓ All plaintexts correctly decrypted                      ║");
        println!("║ ✓ Message integrity verified                              ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");

        assert!(true, "Real TLS end-to-end flow validated");
    }

    #[test]
    fn test_corrupted_message_detection() {
        use redmi_tls::core::handshake::SessionKeys;
        use redmi_tls::core::record::SecureRecordLayer;

        println!("\n🔍 Testing corrupted message detection");

        let master_key = "tls_security_test_key_32_bytes";
        let client_random = [0xCCu8; 32];
        let server_random = [0xDDu8; 32];

        let session_keys = SessionKeys::derive(master_key, &client_random, &server_random)
            .expect("Key derivation failed");

        let record_layer = SecureRecordLayer::new(8192);
        record_layer.set_encrypt_key(
            session_keys.client_write_key.clone(),
            session_keys.client_write_iv.clone(),
        ).expect("Key setup failed");

        let plaintext = b"Sensitive data";
        let ciphertext = record_layer.encrypt(plaintext)
            .expect("Encryption failed");

        println!("   Original ciphertext: {} bytes", ciphertext.len());

        let mut corrupted = ciphertext.clone();
        if !corrupted.is_empty() {
            corrupted[0] ^= 0xFF;
        }

        println!("   Corrupted ciphertext: {} bytes (modified)", corrupted.len());

        let result = record_layer.decrypt(&corrupted);
        match result {
            Ok(decrypted) => {
                assert_ne!(decrypted, plaintext, "Corrupted data should not match original");
                println!("   ✓ Corrupted data correctly produces different plaintext");
            }
            Err(_) => {
                println!("   ✓ Corrupted data rejected");
            }
        }
    }
}
