use alloc::vec;
use alloc::vec::Vec;
use anyhow::Result;
use crate::core::handshake::{
    ClientAuthenticator, ClientAuthPolicy,
    EarlyDataManager,
    PSKEncryption,
};
use crate::crypto::CryptoKey;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeMessageType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    ClientKeyExchange = 16,
    CertificateVerify = 15,
    Finished = 20,
}

#[derive(Clone, Debug)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
}

#[derive(Clone, Debug)]
pub struct CertificateMessage {
    pub cert_chain: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ClientKeyExchangeMessage {
    pub encrypted_premaster_secret: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct FinishedMessage {
    pub verify_data: Vec<u8>,
}

pub struct TlsHandshake {
    crypto_key: CryptoKey,
    client_auth: ClientAuthenticator,
    early_data_manager: EarlyDataManager,
    psk_crypto: PSKEncryption,
    state: HandshakeState,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    CertificateReceived,
    ClientKeyExchangeSent,
    Finished,
}

impl TlsHandshake {
    pub fn new(master_key: &str) -> Result<Self> {
        let crypto_key = CryptoKey::new(master_key, "tls_handshake")?;
        let client_auth = ClientAuthenticator::new(ClientAuthPolicy::Required);
        let early_data_manager = EarlyDataManager::new(4096, 300);
        
        let mut key_bytes = [0u8; 32];
        let master_bytes = master_key.as_bytes();
        let copy_len = core::cmp::min(master_bytes.len(), 32);
        key_bytes[..copy_len].copy_from_slice(&master_bytes[..copy_len]);
        
        let psk_crypto = PSKEncryption::new(key_bytes);

        Ok(TlsHandshake {
            crypto_key,
            client_auth,
            early_data_manager,
            psk_crypto,
            state: HandshakeState::Initial,
        })
    }

    pub fn generate_client_hello(&mut self, session_id: Option<Vec<u8>>) -> Result<ClientHello> {
        if self.state != HandshakeState::Initial {
            return Err(anyhow::anyhow!("Invalid handshake state for ClientHello"));
        }

        let mut random = [0u8; 32];
        for i in 0..32 {
            random[i] = ((i as u8) ^ 0xAA) as u8;
        }

        let client_hello = ClientHello {
            version: 0x0303,
            random,
            session_id: session_id.unwrap_or_default(),
            cipher_suites: vec![
                0x002F,
                0x0035,
                0x003C,
                0x003D,
            ],
            compression_methods: vec![0],
        };

        self.state = HandshakeState::ClientHelloSent;
        Ok(client_hello)
    }

    pub fn process_server_hello(&mut self, server_hello: &ServerHello) -> Result<()> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err(anyhow::anyhow!("Invalid handshake state for ServerHello"));
        }

        if server_hello.version != 0x0303 {
            return Err(anyhow::anyhow!("Unsupported TLS version: 0x{:04X}", server_hello.version));
        }

        self.state = HandshakeState::ServerHelloReceived;
        Ok(())
    }

    pub fn process_certificate(&mut self, cert_message: &CertificateMessage) -> Result<()> {
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(anyhow::anyhow!("Invalid handshake state for Certificate"));
        }

        if cert_message.cert_chain.is_empty() {
            return Err(anyhow::anyhow!("Empty certificate chain"));
        }

        for (idx, cert_bytes) in cert_message.cert_chain.iter().enumerate() {
            if cert_bytes.is_empty() {
                return Err(anyhow::anyhow!("Empty certificate at index {}", idx));
            }
        }

        let _auth_used = &self.client_auth;
        
        let _early_stats = &self.early_data_manager;

        self.state = HandshakeState::CertificateReceived;
        Ok(())
    }

    pub fn generate_client_key_exchange(&mut self) -> Result<ClientKeyExchangeMessage> {
        if self.state != HandshakeState::CertificateReceived {
            return Err(anyhow::anyhow!("Invalid handshake state for ClientKeyExchange"));
        }

        let premaster_secret = b"premaster_secret_48_bytes_long_dummy_value_1234";
        let encrypted_str = self.crypto_key.encrypt(premaster_secret)?;
        let encrypted = encrypted_str.as_bytes().to_vec();

        self.state = HandshakeState::ClientKeyExchangeSent;
        Ok(ClientKeyExchangeMessage {
            encrypted_premaster_secret: encrypted,
        })
    }

    pub fn generate_finished(&mut self) -> Result<FinishedMessage> {
        if self.state != HandshakeState::ClientKeyExchangeSent {
            return Err(anyhow::anyhow!("Invalid handshake state for Finished"));
        }

        let verify_data = b"finished_verify_data_dummy";
        let finished_str = self.crypto_key.encrypt(verify_data)?;
        let finished_msg = finished_str.as_bytes().to_vec();

        self.state = HandshakeState::Finished;
        Ok(FinishedMessage {
            verify_data: finished_msg,
        })
    }

    pub fn verify_server_finished(&mut self, finished: &FinishedMessage) -> Result<()> {
        if self.state != HandshakeState::Finished {
            return Err(anyhow::anyhow!("Invalid handshake state for ServerFinished verification"));
        }

        let finished_str = alloc::string::String::from_utf8(finished.verify_data.clone())
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in finished data"))?;
        
        let decrypted = self.crypto_key.decrypt(&finished_str)
            .ok_or_else(|| anyhow::anyhow!("Failed to decrypt finished message"))?;
        
        if decrypted != b"finished_verify_data_dummy" {
            return Err(anyhow::anyhow!("Server Finished verification failed"));
        }

        Ok(())
    }

    pub fn complete_with_psk(&mut self, psk: Option<&[u8]>) -> Result<()> {
        if let Some(psk_data) = psk {
            self.psk_crypto.store_psk_encrypted("default_psk", psk_data)?;
        }
        Ok(())
    }

    pub fn get_state(&self) -> HandshakeState {
        self.state
    }

    pub fn reset(&mut self) {
        self.state = HandshakeState::Initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() {
        let mut handshake = TlsHandshake::new("test_master_key").expect("Failed to create handshake");
        
        let client_hello = handshake.generate_client_hello(None).expect("Failed to generate ClientHello");
        assert_eq!(client_hello.version, 0x0303);
        assert!(!client_hello.cipher_suites.is_empty());
        
        let server_hello = ServerHello {
            version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: 0x002F,
            compression_method: 0,
        };
        
        handshake.process_server_hello(&server_hello).expect("Failed to process ServerHello");
        
        let cert_msg = CertificateMessage {
            cert_chain: vec![b"dummy_certificate_data".to_vec()],
        };
        
        handshake.process_certificate(&cert_msg).expect("Failed to process Certificate");
        
        let key_exchange = handshake.generate_client_key_exchange().expect("Failed to generate ClientKeyExchange");
        assert!(!key_exchange.encrypted_premaster_secret.is_empty());
        
        let finished = handshake.generate_finished().expect("Failed to generate Finished");
        assert!(!finished.verify_data.is_empty());
    }

    #[test]
    fn test_handshake_state_validation() {
        let mut handshake = TlsHandshake::new("test_master_key").expect("Failed to create handshake");
        
        let server_hello = ServerHello {
            version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: 0x002F,
            compression_method: 0,
        };
        
        let result = handshake.process_server_hello(&server_hello);
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_handshake() {
        let mut handshake = TlsHandshake::new("test_master_key").expect("Failed to create handshake");
        
        let _ = handshake.generate_client_hello(None);
        assert_eq!(handshake.get_state(), HandshakeState::ClientHelloSent);
        
        handshake.reset();
        assert_eq!(handshake.get_state(), HandshakeState::Initial);
    }
}
