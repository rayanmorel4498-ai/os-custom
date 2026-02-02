extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Debug)]
pub struct PooledConnection {
    pub conn_id: u64,
    pub peer_addr: Vec<u8>,
    pub is_active: bool,
    pub last_used: u64,
    pub created_at: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

pub struct ConnectionPool {
    connections: Arc<RwLock<BTreeMap<u64, PooledConnection>>>,
    next_conn_id: Arc<AtomicU64>,
    max_pool_size: usize,
    idle_timeout_secs: u64,
    created: Arc<AtomicU64>,
    reused: Arc<AtomicU64>,
    closed: Arc<AtomicU64>,
}

impl ConnectionPool {
    pub fn new(max_pool_size: usize, idle_timeout_secs: u64) -> Self {
        Self {
            connections: Arc::new(RwLock::new(BTreeMap::new())),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            max_pool_size,
            idle_timeout_secs,
            created: Arc::new(AtomicU64::new(0)),
            reused: Arc::new(AtomicU64::new(0)),
            closed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_connection(&self, peer_addr: Vec<u8>) -> u64 {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        
        let conn = PooledConnection {
            conn_id,
            peer_addr,
            is_active: true,
            last_used: Self::current_time(),
            created_at: Self::current_time(),
            bytes_sent: 0,
            bytes_recv: 0,
        };

        let mut pool = self.connections.write();
        pool.insert(conn_id, conn);

        if pool.len() > self.max_pool_size {
            if let Some(first_id) = pool.keys().next().cloned() {
                pool.remove(&first_id);
                self.closed.fetch_add(1, Ordering::SeqCst);
            }
        }

        self.created.fetch_add(1, Ordering::SeqCst);
        conn_id
    }

    pub fn get_connection(&self, conn_id: u64) -> Option<PooledConnection> {
        let mut pool = self.connections.write();
        let conn = pool.get_mut(&conn_id)?;

        if !conn.is_active {
            return None;
        }

        let now = Self::current_time();
        if now.saturating_sub(conn.last_used) > self.idle_timeout_secs {
            conn.is_active = false;
            return None;
        }

        conn.last_used = now;
        self.reused.fetch_add(1, Ordering::SeqCst);
        Some(conn.clone())
    }

    pub fn find_connection(&self, peer_addr: &[u8]) -> Option<u64> {
        let pool = self.connections.read();
        let now = Self::current_time();

        for (id, conn) in pool.iter() {
            if conn.peer_addr == peer_addr && conn.is_active {
                if now.saturating_sub(conn.last_used) <= self.idle_timeout_secs {
                    return Some(*id);
                }
            }
        }
        None
    }

    pub fn record_traffic(&self, conn_id: u64, sent: u64, recv: u64) -> bool {
        let mut pool = self.connections.write();
        if let Some(conn) = pool.get_mut(&conn_id) {
            conn.bytes_sent = conn.bytes_sent.saturating_add(sent);
            conn.bytes_recv = conn.bytes_recv.saturating_add(recv);
            conn.last_used = Self::current_time();
            return true;
        }
        false
    }

    pub fn close_connection(&self, conn_id: u64) -> bool {
        if self.connections.write().remove(&conn_id).is_some() {
            self.closed.fetch_add(1, Ordering::SeqCst);
            return true;
        }
        false
    }

    pub fn cleanup_idle(&self) -> usize {
        let mut pool = self.connections.write();
        let now = Self::current_time();
        let initial_len = pool.len();

        pool.retain(|_, conn| {
            if now.saturating_sub(conn.last_used) > self.idle_timeout_secs {
                self.closed.fetch_add(1, Ordering::SeqCst);
                false
            } else {
                true
            }
        });

        initial_len - pool.len()
    }

    pub fn stats(&self) -> ConnectionPoolStats {
        let pool = self.connections.read();
        let now = Self::current_time();

        let mut active = 0;
        let mut idle = 0;
        let mut total_bytes_sent = 0;
        let mut total_bytes_recv = 0;

        for conn in pool.values() {
            if conn.is_active {
                if now.saturating_sub(conn.last_used) <= self.idle_timeout_secs {
                    active += 1;
                } else {
                    idle += 1;
                }
            }
            total_bytes_sent += conn.bytes_sent;
            total_bytes_recv += conn.bytes_recv;
        }

        ConnectionPoolStats {
            total_connections: pool.len(),
            active_connections: active,
            idle_connections: idle,
            created_count: self.created.load(Ordering::SeqCst),
            reused_count: self.reused.load(Ordering::SeqCst),
            closed_count: self.closed.load(Ordering::SeqCst),
            total_bytes_sent,
            total_bytes_recv,
        }
    }

    pub fn clear_all(&self) {
        self.connections.write().clear();
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
pub struct ConnectionPoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub created_count: u64,
    pub reused_count: u64,
    pub closed_count: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_connection() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        let conn_id = pool.add_connection(peer);
        assert_eq!(conn_id, 1);
    }

    #[test]
    fn test_get_connection() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        let conn_id = pool.add_connection(peer);
        let conn = pool.get_connection(conn_id);
        
        assert!(conn.is_some());
    }

    #[test]
    fn test_find_connection() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        let conn_id = pool.add_connection(peer.clone());
        let found_id = pool.find_connection(&peer);
        
        assert_eq!(found_id, Some(conn_id));
    }

    #[test]
    fn test_record_traffic() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        let conn_id = pool.add_connection(peer);
        assert!(pool.record_traffic(conn_id, 1024, 2048));
    }

    #[test]
    fn test_close_connection() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        let conn_id = pool.add_connection(peer);
        assert!(pool.close_connection(conn_id));
    }

    #[test]
    fn test_stats() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        pool.add_connection(peer);
        let stats = pool.stats();
        
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.created_count, 1);
    }

    #[test]
    fn test_clear_all() {
        let pool = ConnectionPool::new(10, 3600);
        let peer = b"127.0.0.1:443".to_vec();
        
        pool.add_connection(peer);
        pool.clear_all();
        
        assert_eq!(pool.stats().total_connections, 0);
    }
}
