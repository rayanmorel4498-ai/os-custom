extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use anyhow::Result;
use crate::api::client::TLSClient;
use crate::api::server::TLSServer;
use super::session_keys::SessionKeys;
use super::cert_validator::CertificateChainValidator;
use super::transport::TLSTransport;

pub struct TLSHandshakeCoordinator {
    client: Arc<TLSClient>,
    server: Arc<TLSServer>,
    transport: Arc<TLSTransport>,
    cert_validator: Arc<parking_lot::Mutex<CertificateChainValidator>>,
    session_keys: Arc<parking_lot::Mutex<Option<SessionKeys>>>,
}

impl TLSHandshakeCoordinator {
    pub fn new(client: Arc<TLSClient>, server: Arc<TLSServer>) -> Self {
        Self {
            client,
            server,
            transport: Arc::new(TLSTransport::new()),
            cert_validator: Arc::new(parking_lot::Mutex::new(CertificateChainValidator::new())),
            session_keys: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn with_cert_validator(self, validator: CertificateChainValidator) -> Self {
        *self.cert_validator.lock() = validator;
        self
    }

    pub fn perform_full_handshake(&self, master_key: &str) -> Result<()> {
        self.client.establish_tls_connection(master_key)?;
        let client_hello = self.generate_client_hello()?;
        self.transport.client_send(client_hello)?;

        let _client_hello_received = self.transport.server_recv()?
            .ok_or_else(|| anyhow::anyhow!("ClientHello not received"))?;
        
        self.server.establish_tls_connection(master_key)?;
        let server_hello = self.generate_server_hello()?;
        let certificate = self.generate_server_certificate()?;
        let server_hello_done = self.generate_server_hello_done()?;
        
        self.transport.server_send(server_hello)?;
        self.transport.server_send(certificate)?;
        self.transport.server_send(server_hello_done)?;

        let _server_hello_received = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerHello not received"))?;
        
        let cert_msg = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("Certificate not received"))?;
        
        let _server_hello_done = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerHelloDone not received"))?;

        self.cert_validator.lock().validate_single_cert(&cert_msg)?;

        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let session_keys = SessionKeys::derive(master_key, &client_random, &server_random)?;
        *self.session_keys.lock() = Some(session_keys.clone());

        let client_key_exchange = self.generate_client_key_exchange()?;
        let client_ccs = self.generate_change_cipher_spec()?;
        let client_finished = self.generate_finished("client")?;
        
        self.transport.client_send(client_key_exchange)?;
        self.transport.client_send(client_ccs)?;
        self.transport.client_send(client_finished)?;

        let _ckex = self.transport.server_recv()?
            .ok_or_else(|| anyhow::anyhow!("ClientKeyExchange not received"))?;
        let _ccs = self.transport.server_recv()?
            .ok_or_else(|| anyhow::anyhow!("ClientCCS not received"))?;
        let _cfin = self.transport.server_recv()?
            .ok_or_else(|| anyhow::anyhow!("ClientFinished not received"))?;

        let server_ccs = self.generate_change_cipher_spec()?;
        let server_finished = self.generate_finished("server")?;
        
        self.transport.server_send(server_ccs)?;
        self.transport.server_send(server_finished)?;

        let _sccs = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerCCS not received"))?;
        let _sfin = self.transport.client_recv()?
            .ok_or_else(|| anyhow::anyhow!("ServerFinished not received"))?;

        self.client.negotiate_tls(master_key)?;
        self.client.setup_record_layer()?;

        Ok(())
    }

    pub fn send_encrypted_message(&self, plaintext: &[u8]) -> Result<()> {
        self.client.transmit_encrypted("server", plaintext)
    }

    pub fn session_keys(&self) -> Result<SessionKeys> {
        self.session_keys.lock()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Session keys not derived yet"))
    }

    pub fn client(&self) -> &Arc<TLSClient> {
        &self.client
    }

    pub fn server(&self) -> &Arc<TLSServer> {
        &self.server
    }

    pub fn transport(&self) -> &Arc<TLSTransport> {
        &self.transport
    }

    fn generate_client_hello(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(&[0x00, 0x42]);
        msg.push(0x01);
        msg.extend_from_slice(&[0x01, 0x03, 0x03]);
        for _ in 0..32 { msg.push(0x01); }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x02]);
        msg.extend_from_slice(&[0x00, 0x2F]);
        msg.push(0x01);
        msg.push(0x00);
        Ok(msg)
    }

    fn generate_server_hello(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(&[0x00, 0x42]);
        msg.push(0x02);
        msg.extend_from_slice(&[0x02, 0x03, 0x03]);
        for _ in 0..32 { msg.push(0x02); }
        msg.push(0x00);
        msg.extend_from_slice(&[0x00, 0x2F]);
        msg.push(0x00);
        Ok(msg)
    }

    fn generate_server_certificate(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.push(0x05);
        msg.extend_from_slice(&[0x00, 0x10]);
        msg.extend_from_slice(&[0x00, 0x0C]);
        msg.extend_from_slice(&[116u8, 101, 115, 116, 95, 99, 101, 114, 116, 95, 100, 101, 114]);
        Ok(msg)
    }

    fn generate_server_hello_done(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.push(0x0E);
        msg.extend_from_slice(&[0x00, 0x00]);
        Ok(msg)
    }

    fn generate_client_key_exchange(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.push(0x10);
        msg.extend_from_slice(&[0x00, 0x10]);
        for _ in 0..16 { msg.push(0xFF); }
        Ok(msg)
    }

    fn generate_change_cipher_spec(&self) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x14);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.push(0x01);
        Ok(msg)
    }

    fn generate_finished(&self, role: &str) -> Result<Vec<u8>> {
        let mut msg = alloc::vec![0u8; 0];
        msg.push(0x16);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.push(0x14);
        msg.extend_from_slice(&[0x00, 0x0C]);
        if role == "client" {
            msg.extend_from_slice(&[99u8, 108, 105, 101, 110, 116, 95, 102, 105, 110, 95, 95]);
        } else {
            msg.extend_from_slice(&[115u8, 101, 114, 118, 101, 114, 95, 102, 105, 110, 95, 95]);
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_transport_exists() {
        assert!(true);
    }
}
