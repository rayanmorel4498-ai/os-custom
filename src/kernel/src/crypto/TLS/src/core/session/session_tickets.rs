extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Debug)]
pub struct SessionTicket {
    pub ticket_id: Vec<u8>,
    pub session_key: Vec<u8>,
    pub created_at: u64,
    pub lifetime_secs: u64,
    pub client_identity: Vec<u8>,
    pub reuse_count: u64,
}

impl SessionTicket {
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) < self.lifetime_secs
    }
}

pub struct SessionTicketManager {
    tickets: Arc<RwLock<BTreeMap<Vec<u8>, SessionTicket>>>,
    default_lifetime: u64,
    max_tickets: usize,
    created: Arc<AtomicU64>,
    reused: Arc<AtomicU64>,
    expired: Arc<AtomicU64>,
}

impl SessionTicketManager {
    pub fn new(default_lifetime: u64, max_tickets: usize) -> Self {
        Self {
            tickets: Arc::new(RwLock::new(BTreeMap::new())),
            default_lifetime,
            max_tickets,
            created: Arc::new(AtomicU64::new(0)),
            reused: Arc::new(AtomicU64::new(0)),
            expired: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn create_ticket(&self, session_key: Vec<u8>, client_identity: Vec<u8>) -> Vec<u8> {
        let ticket_id = Self::generate_ticket_id();
        
        let ticket = SessionTicket {
            ticket_id: ticket_id.clone(),
            session_key,
            created_at: Self::current_time(),
            lifetime_secs: self.default_lifetime,
            client_identity,
            reuse_count: 0,
        };

        let mut store = self.tickets.write();
        store.insert(ticket_id.clone(), ticket);
        
        if store.len() > self.max_tickets {
            if let Some(first_key) = store.keys().next().cloned() {
                store.remove(&first_key);
            }
        }

        self.created.fetch_add(1, Ordering::SeqCst);
        ticket_id
    }

    pub fn reuse_ticket(&self, ticket_id: &[u8]) -> Option<SessionTicket> {
        let mut store = self.tickets.write();
        let ticket = store.get_mut(ticket_id)?;

        let now = Self::current_time();
        if !ticket.is_valid(now) {
            self.expired.fetch_add(1, Ordering::SeqCst);
            return None;
        }

        ticket.reuse_count += 1;
        self.reused.fetch_add(1, Ordering::SeqCst);
        Some(ticket.clone())
    }

    pub fn get_ticket(&self, ticket_id: &[u8]) -> Option<SessionTicket> {
        let store = self.tickets.read();
        let ticket = store.get(ticket_id)?;

        let now = Self::current_time();
        if ticket.is_valid(now) {
            Some(ticket.clone())
        } else {
            None
        }
    }

    pub fn has_valid_ticket(&self, ticket_id: &[u8]) -> bool {
        let store = self.tickets.read();
        if let Some(ticket) = store.get(ticket_id) {
            ticket.is_valid(Self::current_time())
        } else {
            false
        }
    }

    pub fn revoke_ticket(&self, ticket_id: &[u8]) -> bool {
        self.tickets.write().remove(ticket_id).is_some()
    }

    pub fn update_lifetime(&self, ticket_id: &[u8], new_lifetime: u64) -> bool {
        let mut store = self.tickets.write();
        if let Some(ticket) = store.get_mut(ticket_id) {
            ticket.lifetime_secs = new_lifetime;
            return true;
        }
        false
    }

    pub fn stats(&self) -> SessionTicketStats {
        let store = self.tickets.read();
        SessionTicketStats {
            total_tickets: store.len(),
            created_count: self.created.load(Ordering::SeqCst),
            reused_count: self.reused.load(Ordering::SeqCst),
            expired_count: self.expired.load(Ordering::SeqCst),
        }
    }

    pub fn cleanup_expired(&self) {
        let mut store = self.tickets.write();
        let now = Self::current_time();
        
        store.retain(|_, ticket| ticket.is_valid(now));
    }

    pub fn clear_all(&self) {
        self.tickets.write().clear();
    }

    fn generate_ticket_id() -> Vec<u8> {
        let time = Self::current_time();
        alloc::format!("ticket_{:016x}", time).into_bytes()
    }

    fn current_time() -> u64 {
        #[cfg(feature = "real_tls")]
        {
            
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
        #[cfg(not(feature = "real_tls"))]
        {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionTicketStats {
    pub total_tickets: usize,
    pub created_count: u64,
    pub reused_count: u64,
    pub expired_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ticket() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key, identity);
        assert!(!ticket_id.is_empty());
    }

    #[test]
    fn test_reuse_ticket() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key, identity);
        let reused = mgr.reuse_ticket(&ticket_id);
        
        assert!(reused.is_some());
        assert_eq!(reused.unwrap().reuse_count, 1);
    }

    #[test]
    fn test_get_ticket() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key.clone(), identity);
        let ticket = mgr.get_ticket(&ticket_id);
        
        assert!(ticket.is_some());
        assert_eq!(ticket.unwrap().session_key, key);
    }

    #[test]
    fn test_has_valid_ticket() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key, identity);
        assert!(mgr.has_valid_ticket(&ticket_id));
    }

    #[test]
    fn test_revoke_ticket() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key, identity);
        assert!(mgr.revoke_ticket(&ticket_id));
        assert!(!mgr.has_valid_ticket(&ticket_id));
    }

    #[test]
    fn test_update_lifetime() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        let ticket_id = mgr.create_ticket(key, identity);
        assert!(mgr.update_lifetime(&ticket_id, 7200));
    }

    #[test]
    fn test_stats() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        mgr.create_ticket(key, identity);
        let stats = mgr.stats();
        
        assert_eq!(stats.created_count, 1);
        assert_eq!(stats.total_tickets, 1);
    }

    #[test]
    fn test_clear_all() {
        let mgr = SessionTicketManager::new(3600, 100);
        let key = b"session_key".to_vec();
        let identity = b"client1".to_vec();
        
        mgr.create_ticket(key, identity);
        mgr.clear_all();
        
        assert_eq!(mgr.stats().total_tickets, 0);
    }
}
