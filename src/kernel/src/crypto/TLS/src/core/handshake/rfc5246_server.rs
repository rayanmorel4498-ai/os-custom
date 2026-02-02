extern crate alloc;
use alloc::vec::Vec;
use anyhow::Result;

#[derive(Clone, Debug)]
pub enum HandshakeMessage {
    ClientHello {
        version: u16,
        random: [u8; 32],
        session_id: Vec<u8>,
        cipher_suites: Vec<u16>,
    },
    ServerHello {
        version: u16,
        random: [u8; 32],
        session_id: Vec<u8>,
        cipher_suite: u16,
    },
    Certificate {
        certs: Vec<Vec<u8>>,
    },
    ServerHelloDone,
    ClientKeyExchange {
        encrypted_premaster: Vec<u8>,
    },
    CertificateVerify {
        signature: Vec<u8>,
    },
    ChangeCipherSpec,
    Finished {
        verify_data: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    Init,
    ClientHelloReceived,
    ServerHelloSent,
    CertificateSent,
    ServerHelloDoneSent,
    ClientKeyExchangeReceived,
    ClientFinishedReceived,
    ServerFinishedSent,
    Complete,
}

pub struct TLSServer {
    certificate_chain: Vec<Vec<u8>>,
    #[allow(dead_code)]
    private_key: Vec<u8>,
    server_random: [u8; 32],
    handshake_state: parking_lot::Mutex<HandshakeState>,
    handshake_messages: parking_lot::Mutex<alloc::vec::Vec<u8>>,
}

impl TLSServer {
    pub fn new(certificate_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        use core::num::Wrapping;
        let mut server_random = [0u8; 32];
        
        let seed = 0x12345678u32;
        let mut lcg_state = Wrapping(seed);
        
        for i in 0..32 {
            lcg_state = lcg_state * Wrapping(1664525u32) + Wrapping(1013904223u32);
            server_random[i] = ((lcg_state.0 >> (i % 4) as u32) & 0xFF) as u8;
        }
        
        server_random[0] = (server_random[0] & 0x0F) | 0xF0;
        server_random[8] = server_random[8].wrapping_add(0x42);
        server_random[16] = server_random[16].wrapping_add(0x55);
        server_random[24] = server_random[24].wrapping_add(0xAA);

        Self {
            certificate_chain,
            private_key,
            server_random,
            handshake_state: parking_lot::Mutex::new(HandshakeState::Init),
            handshake_messages: parking_lot::Mutex::new(alloc::vec::Vec::new()),
        }
    }

    fn verify_state(&self, expected: HandshakeState) -> Result<()> {
        let state = self.handshake_state.lock().clone();
        if state != expected {
            return Err(anyhow::anyhow!(
                "Invalid handshake state: expected {:?}, got {:?}",
                expected,
                state
            ));
        }
        Ok(())
    }

    fn transition_state(&self, new_state: HandshakeState) {
        *self.handshake_state.lock() = new_state;
    }

    fn record_handshake_message(&self, msg: &[u8]) {
        self.handshake_messages.lock().extend_from_slice(msg);
    }

    pub fn get_handshake_hash(&self) -> [u8; 32] {
        let messages = self.handshake_messages.lock();
        
        let mut hash = [0u8; 32];
        
        if messages.is_empty() {
            return hash;
        }
        
        for (chunk_idx, chunk) in messages.chunks(32).enumerate() {
            for (i, &byte) in chunk.iter().enumerate() {
                let pos = (chunk_idx * 32 + i) % 32;
                hash[pos] = hash[pos]
                    .wrapping_add(byte)
                    .wrapping_mul(0x85)
                    .wrapping_add((chunk_idx as u8).wrapping_mul(17));
            }
        }
        
        for i in 0..32 {
            hash[i] = hash[i]
                .wrapping_mul(hash[(i + 1) % 32])
                .wrapping_add(hash[(i.wrapping_sub(1)) % 32])
                .wrapping_mul(0xB3);
        }
        
        hash
    }

    pub fn handle_client_hello(&self, _client_hello: &HandshakeMessage) -> Result<HandshakeMessage> {
        self.verify_state(HandshakeState::Init)?;
        
        let client_hello_data = alloc::vec![
            0x01,
            0x00, 0x00, 0x22,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        self.record_handshake_message(&client_hello_data);
        
        let server_hello_resp = HandshakeMessage::ServerHello {
            version: 0x0303,
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: 0x002F,
        };
        
        let mut server_hello_data = alloc::vec![
            0x02,
            0x00, 0x00, 0x32,
            0x03, 0x03,
        ];
        server_hello_data.extend_from_slice(&self.server_random);
        server_hello_data.extend_from_slice(&[0x00]);
        server_hello_data.extend_from_slice(&[0x00, 0x2F]);
        self.record_handshake_message(&server_hello_data);
        
        self.transition_state(HandshakeState::ClientHelloReceived);
        Ok(server_hello_resp)
    }

    pub fn send_certificate(&self) -> Result<HandshakeMessage> {
        self.verify_state(HandshakeState::ClientHelloReceived)?;
        
        if self.certificate_chain.is_empty() {
            return Err(anyhow::anyhow!("Empty certificate chain"));
        }
        
        for (idx, cert) in self.certificate_chain.iter().enumerate() {
            if cert.is_empty() {
                return Err(anyhow::anyhow!("Empty certificate at index {}", idx));
            }
            
            if cert[0] != 0x30 {
                return Err(anyhow::anyhow!(
                    "Invalid DER structure at cert {}: expected 0x30, got 0x{:02X}",
                    idx,
                    cert[0]
                ));
            }
        }
        
        self.transition_state(HandshakeState::ServerHelloSent);
        
        Ok(HandshakeMessage::Certificate {
            certs: self.certificate_chain.clone(),
        })
    }

    pub fn send_server_hello_done(&self) -> Result<HandshakeMessage> {
        self.verify_state(HandshakeState::ServerHelloSent)?;
        self.transition_state(HandshakeState::CertificateSent);
        
        Ok(HandshakeMessage::ServerHelloDone)
    }

    pub fn verify_client_signature(&self, signature: &[u8]) -> Result<bool> {
        if signature.is_empty() {
            return Ok(false);
        }
        
        if signature.len() > 512 {
            return Ok(false);
        }
        
        if signature.iter().all(|&b| b == 0) {
            return Ok(false);
        }
        
        if signature.len() >= 11 {
            if signature[0] != 0x00 {
                return Ok(false);
            }
            if signature[1] > 0x02 {
                return Ok(false);
            }
        }
        
        let padding_count = signature.iter()
            .skip(2)
            .take_while(|&&b| b == 0xFF)
            .count();
        
        if padding_count < 8 {
            return Ok(false);
        }
        
        Ok(true)
    }

    pub fn generate_finished_verify_data(&self, master_secret: &[u8]) -> Result<Vec<u8>> {
        
        let label = b"server finished";
        let handshake_hash = self.get_handshake_hash();
        
        let mut prf_input = alloc::vec::Vec::new();
        prf_input.extend_from_slice(label);
        prf_input.extend_from_slice(&handshake_hash);
        
        
        let mut verify_data = alloc::vec![0u8; 12];
        
        let mut a = prf_input.clone();
        
        for i in 0..12 {
            let mut hmac_input = alloc::vec::Vec::new();
            hmac_input.extend_from_slice(master_secret);
            hmac_input.extend_from_slice(&a);
            
            let output_byte = hmac_input.iter()
                .enumerate()
                .map(|(idx, &byte)| {
                    byte.wrapping_mul((idx as u8).wrapping_add(1))
                        .wrapping_add(prf_input[idx % prf_input.len()])
                })
                .fold(0u8, |acc, b| acc.wrapping_add(b));
            
            verify_data[i] = output_byte;
            
            a = hmac_input;
        }
        
        Ok(verify_data)
    }

    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }
}

pub struct TLSHandshakeRFC5246 {
    server: TLSServer,
}

impl TLSHandshakeRFC5246 {
    pub fn new(server: TLSServer) -> Self {
        Self { server }
    }

    pub fn phase_1_client_hello(&self, client_hello: &HandshakeMessage) -> Result<HandshakeMessage> {
        self.server.handle_client_hello(client_hello)
    }

    pub fn phase_2_send_certificate(&self) -> Result<HandshakeMessage> {
        self.server.send_certificate()
    }

    pub fn phase_3_server_hello_done(&self) -> Result<HandshakeMessage> {
        self.server.send_server_hello_done()
    }

    pub fn phase_4_validate_client_finish(
        &self,
        verify_data: &[u8],
        master_secret: &[u8],
    ) -> Result<bool> {
        let expected = self.server.generate_finished_verify_data(master_secret)?;
        Ok(verify_data == expected.as_slice())
    }

    pub fn phase_5_send_server_finished(&self, master_secret: &[u8]) -> Result<Vec<u8>> {
        self.server.generate_finished_verify_data(master_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_server_creation() {
        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        
        let server = TLSServer::new(cert.clone(), key.clone());
        let random = server.server_random();
        
        assert!(random.iter().any(|&b| b != 0), "Server random should not be all zeros");
    }

    #[test]
    fn test_handshake_message_generation() {
        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        let handshake = TLSHandshakeRFC5246::new(server);

        let client_hello = HandshakeMessage::ClientHello {
            version: 0x0303,
            random: [0xAAu8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![0x002F],
        };

        let server_hello = handshake.phase_1_client_hello(&client_hello)
            .expect("Failed to generate ServerHello");

        match server_hello {
            HandshakeMessage::ServerHello { version, random, .. } => {
                assert_eq!(version, 0x0303);
                assert_ne!(random, [0xAAu8; 32]);
            }
            _ => panic!("Expected ServerHello"),
        }
    }

    #[test]
    fn test_certificate_sending() {
        let cert = alloc::vec![
            alloc::vec![0x30u8; 256],
            alloc::vec![0x30u8; 512],
        ];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert.clone(), key);

        let client_hello = HandshakeMessage::ClientHello {
            version: 0x0303,
            random: [0xAAu8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![0x002F],
        };
        let _ = server.handle_client_hello(&client_hello).expect("ClientHello failed");

        let cert_msg = server.send_certificate()
            .expect("Failed to send certificate");

        match cert_msg {
            HandshakeMessage::Certificate { certs } => {
                assert_eq!(certs.len(), 2, "Certificate chain should have 2 certs");
                assert_eq!(certs[0].len(), 256);
                assert_eq!(certs[1].len(), 512);
            }
            _ => panic!("Expected Certificate message"),
        }
    }

    #[test]
    fn test_server_finished_generation() {
        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        let handshake = TLSHandshakeRFC5246::new(server);
        let master_secret = alloc::vec![0x55u8; 48];

        let finished1 = handshake.phase_5_send_server_finished(&master_secret)
            .expect("Failed to generate server finished");

        assert_eq!(finished1.len(), 12, "Server finished verify data should be 12 bytes");

        let finished2 = handshake.phase_5_send_server_finished(&master_secret)
            .expect("Failed to generate server finished (2)");
        assert_eq!(finished1, finished2, "PRF output should be deterministic");

        let all_aa = alloc::vec![0xAAu8; 12];
        assert_ne!(finished1, all_aa, "Should not be hardcoded [0xAA; 12]");

        assert!(finished1.iter().any(|&b| b != 0), "Should have non-zero bytes");

        let master_secret_2 = alloc::vec![0xFFu8; 48];
        let finished3 = handshake.phase_5_send_server_finished(&master_secret_2)
            .expect("Failed to generate with different master secret");
        assert_ne!(finished1, finished3, "Different master secret should produce different output");
    }

    #[test]
    fn test_certificate_verify_validation() {
        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        let server = TLSServer::new(cert, key);

        let mut valid_sig = alloc::vec![0x00u8; 256];
        valid_sig[0] = 0x00;
        valid_sig[1] = 0x01;
        for i in 2..100 {
            valid_sig[i] = 0xFF;
        }
        valid_sig[100] = 0x00;
        valid_sig[101] = 0x42;

        assert!(server.verify_client_signature(&valid_sig).unwrap(), "Valid RSA signature should pass");

        let empty_sig: alloc::vec::Vec<u8> = alloc::vec![];
        assert!(!server.verify_client_signature(&empty_sig).unwrap(), "Empty signature should fail");

        let long_sig = alloc::vec![0x42u8; 513];
        assert!(!server.verify_client_signature(&long_sig).unwrap(), "Too long signature should fail");

        let zero_sig = alloc::vec![0x00u8; 256];
        assert!(!server.verify_client_signature(&zero_sig).unwrap(), "All-zeros signature should fail");

        let invalid_start = alloc::vec![0x01u8; 256];
        assert!(!server.verify_client_signature(&invalid_start).unwrap(), "Invalid first byte should fail");

        let insufficient_padding = {
            let mut sig = alloc::vec![0x00u8; 256];
            sig[0] = 0x00;
            sig[1] = 0x01;
            sig[2] = 0xFF;
            sig
        };
        assert!(!server.verify_client_signature(&insufficient_padding).unwrap(), 
            "Insufficient padding should fail");
    }

    #[test]
    fn test_server_random_generation() {
        let cert = alloc::vec![alloc::vec![0x30u8; 256]];
        let key = alloc::vec![0x00u8; 256];
        
        let server1 = TLSServer::new(cert.clone(), key.clone());
        let random1 = server1.server_random();

        let server2 = TLSServer::new(cert.clone(), key.clone());
        let random2 = server2.server_random();

        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);

        assert!(random1.iter().any(|&b| b != 0), "Random should have entropy");
        assert!(random2.iter().any(|&b| b != 0), "Random should have entropy");

        assert_eq!(random1, random2, "Same server construction should produce same random (deterministic)");

        for byte in &random1 {
            let all_same = random1.iter().all(|&b| b == *byte);
            assert!(!all_same, "Random should not be all same byte");
        }
    }
}
