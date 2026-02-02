extern crate alloc;

use alloc::vec::Vec;
use anyhow::Result;
use parking_lot::Mutex;

pub struct TLSTransport {
    client_to_server: Mutex<Vec<Vec<u8>>>,
    server_to_client: Mutex<Vec<Vec<u8>>>,
}

impl TLSTransport {
    pub fn new() -> Self {
        Self {
            client_to_server: Mutex::new(Vec::new()),
            server_to_client: Mutex::new(Vec::new()),
        }
    }

    pub fn client_send(&self, message: Vec<u8>) -> Result<()> {
        self.client_to_server.lock().push(message);
        Ok(())
    }

    pub fn client_recv(&self) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.server_to_client.lock();
        if buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buffer.remove(0)))
        }
    }

    pub fn server_send(&self, message: Vec<u8>) -> Result<()> {
        self.server_to_client.lock().push(message);
        Ok(())
    }

    pub fn server_recv(&self) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.client_to_server.lock();
        if buffer.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buffer.remove(0)))
        }
    }

    pub fn client_to_server_pending(&self) -> usize {
        self.client_to_server.lock().len()
    }

    pub fn server_to_client_pending(&self) -> usize {
        self.server_to_client.lock().len()
    }

    pub fn clear(&self) {
        self.client_to_server.lock().clear();
        self.server_to_client.lock().clear();
    }
}

impl Default for TLSTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_transport_creation() {
        let transport = TLSTransport::new();
        assert_eq!(transport.client_to_server_pending(), 0);
        assert_eq!(transport.server_to_client_pending(), 0);
    }

    #[test]
    fn test_client_send_recv() {
        let transport = TLSTransport::new();
        let msg = vec![0x01, 0x02, 0x03];
        
        transport.client_send(msg.clone()).unwrap();
        assert_eq!(transport.client_to_server_pending(), 1);
        
        let received = transport.server_recv().unwrap();
        assert_eq!(received, Some(msg));
        assert_eq!(transport.client_to_server_pending(), 0);
    }

    #[test]
    fn test_server_send_recv() {
        let transport = TLSTransport::new();
        let msg = vec![0x04, 0x05, 0x06];
        
        transport.server_send(msg.clone()).unwrap();
        assert_eq!(transport.server_to_client_pending(), 1);
        
        let received = transport.client_recv().unwrap();
        assert_eq!(received, Some(msg));
        assert_eq!(transport.server_to_client_pending(), 0);
    }

    #[test]
    fn test_bidirectional_communication() {
        let transport = TLSTransport::new();
        
        transport.client_send(vec![1, 2, 3]).unwrap();
        transport.server_send(vec![4, 5, 6]).unwrap();
        
        let from_server = transport.client_recv().unwrap();
        let from_client = transport.server_recv().unwrap();
        
        assert_eq!(from_server, Some(vec![4, 5, 6]));
        assert_eq!(from_client, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_empty_recv() {
        let transport = TLSTransport::new();
        
        let result = transport.client_recv().unwrap();
        assert_eq!(result, None);
        
        let result = transport.server_recv().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_clear() {
        let transport = TLSTransport::new();
        
        transport.client_send(vec![1, 2, 3]).unwrap();
        transport.server_send(vec![4, 5, 6]).unwrap();
        
        transport.clear();
        
        assert_eq!(transport.client_to_server_pending(), 0);
        assert_eq!(transport.server_to_client_pending(), 0);
    }
}
