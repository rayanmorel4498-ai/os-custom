extern crate alloc;

use alloc::vec::Vec;
use anyhow::Result;
use crate::core::handshake::{SessionKeys, CertificateChainValidator, TLSTransport};
use crate::core::record::SecureRecordLayer;
use crate::security::SecurityLogger;

pub struct TLSClientEngine {
    transport: alloc::sync::Arc<TLSTransport>,
    record_layer: SecureRecordLayer,
    cert_validator: CertificateChainValidator,
    security_logger: SecurityLogger,
    session_keys: parking_lot::Mutex<Option<SessionKeys>>,
    handshake_complete: parking_lot::Mutex<bool>,
}

impl TLSClientEngine {
    pub fn new() -> Self {
        Self {
            transport: alloc::sync::Arc::new(TLSTransport::new()),
            record_layer: SecureRecordLayer::new(16384),
            cert_validator: CertificateChainValidator::new(),
            security_logger: SecurityLogger::new(500),
            session_keys: parking_lot::Mutex::new(None),
            handshake_complete: parking_lot::Mutex::new(false),
        }
    }

    pub fn with_cert_validator(mut self, validator: CertificateChainValidator) -> Self {
        self.cert_validator = validator;
        self
    }

    pub fn perform_handshake(&self, master_key: &str) -> Result<()> {
        self.security_logger.log(
            crate::security::SecurityEvent::ClientHandshakeStart,
            "Starting TLS handshake",
        );

        let client_hello = self.generate_client_hello()?;
        self.transport.client_send(client_hello)?;

        let _server_hello = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerHello not received"))?;


        let certificate = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("Certificate not received"))?;


        match self.cert_validator.validate_single_cert(&certificate) {
            Ok(()) => {
                self.security_logger.log(
                    crate::security::SecurityEvent::CertificateValidationSuccess,
                    "Server certificate validated",
                );
            }
            Err(e) => {
                self.security_logger.log(
                    crate::security::SecurityEvent::CertificateValidationFailed,
                    &alloc::format!("Certificate validation failed: {}", e),
                );
                return Err(e);
            }
        }

        let _server_hello_done = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerHelloDone not received"))?;


        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let session_keys = SessionKeys::derive(master_key, &client_random, &server_random)?;

        self.security_logger.log(
            crate::security::SecurityEvent::SessionKeysDerived,
            "Session keys derived",
        );

        *self.session_keys.lock() = Some(session_keys.clone());

        self.record_layer.set_encrypt_key(
            session_keys.client_write_key.clone(),
            session_keys.client_write_iv.clone(),
        )?;
        self.record_layer.set_decrypt_key(
            session_keys.server_write_key.clone(),
            session_keys.server_write_iv.clone(),
        )?;

        self.security_logger.log(
            crate::security::SecurityEvent::RecordLayerActivated,
            "Record layer configured",
        );

        let client_key_exchange = self.generate_client_key_exchange()?;
        self.transport.client_send(client_key_exchange)?;

        let client_ccs = self.generate_change_cipher_spec()?;
        self.transport.client_send(client_ccs)?;

        let client_finished = self.generate_finished("client")?;
        self.transport.client_send(client_finished)?;

        let _server_ccs = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerCCS not received"))?;

        let _server_finished = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerFinished not received"))?;

        *self.handshake_complete.lock() = true;

        self.security_logger.log(
            crate::security::SecurityEvent::ClientHandshakeSuccess,
            "TLS handshake completed successfully",
        );

        Ok(())
    }

    pub fn send_message(&self, plaintext: &[u8]) -> Result<()> {
        if !*self.handshake_complete.lock() {
            return Err(anyhow::anyhow!("Handshake not complete"));
        }

        let ciphertext = self.record_layer.encrypt(plaintext)?;
        self.transport.client_send(ciphertext)?;
        Ok(())
    }


    pub fn recv_message(&self) -> Result<Option<Vec<u8>>> {
        if !*self.handshake_complete.lock() {
            return Err(anyhow::anyhow!("Handshake not complete"));
        }

        if let Some(ciphertext) = self.transport.client_recv()? {
            let plaintext = self.record_layer.decrypt(&ciphertext)?;
            Ok(Some(plaintext))
        } else {
            Ok(None)
        }
    }

    pub fn is_connected(&self) -> bool {
        *self.handshake_complete.lock()
    }

    pub fn message_count(&self) -> u64 {
        self.record_layer.message_count()
    }

    pub fn cleanup(&self) -> Result<()> {
        self.record_layer.zeroize_keys()?;
        *self.session_keys.lock() = None;
        self.security_logger.log(
            crate::security::SecurityEvent::SensitiveBufferZeroed,
            "Session keys zeroed",
        );
        Ok(())
    }

    pub fn security_logger(&self) -> &SecurityLogger {
        &self.security_logger
    }

    fn generate_client_hello(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(&[0x00, 0x20]);
        msg.push(0x01);
        for _ in 0..32 { msg.push(0x01); }
        Ok(msg)
    }

    fn generate_client_key_exchange(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.push(0x10);
        for _ in 0..16 { msg.push(0xFF); }
        Ok(msg)
    }

    fn generate_change_cipher_spec(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x14);
        msg.push(0x01);
        Ok(msg)
    }

    fn generate_finished(&self, role: &str) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.push(0x14);
        if role == "client" {
            msg.extend_from_slice(&[99u8, 108, 105, 101, 110, 116, 95, 102]);
        } else {
            msg.extend_from_slice(&[115u8, 101, 114, 118, 101, 114, 95, 102]);
        }
        Ok(msg)
    }
}

impl Default for TLSClientEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_engine_creation() {
        let client = TLSClientEngine::new();
        assert!(!client.is_connected());
        assert_eq!(client.message_count(), 0);
    }

    #[test]
    fn test_not_connected_before_handshake() {
        let client = TLSClientEngine::new();
        let result = client.send_message(b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_zeroizes() {
        let client = TLSClientEngine::new();
        let result = client.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn test_security_logger_access() {
        let client = TLSClientEngine::new();
        let logger = client.security_logger();
        assert_eq!(logger.entry_count(), 0);
    }
}
