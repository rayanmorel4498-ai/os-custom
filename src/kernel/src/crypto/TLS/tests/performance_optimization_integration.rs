extern crate alloc;
use redmi_tls::core::{
    EarlyDataManager, SessionTicketManager, HandshakeOptimizer, RecordBatcher
};
use redmi_tls::runtime::{ConnectionPool, MemoryPool, PoolConfig};

#[test]
fn test_early_data_0rtt_integration() {
    let early_data_mgr = EarlyDataManager::new(16384, 3600);
    
    let client_id = b"client_123".to_vec();
    let early_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    
    assert!(early_data_mgr.store_early_data(client_id.clone(), early_payload.clone()));
    
    let retrieved = early_data_mgr.get_early_data(&client_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().data, early_payload);
    
    assert!(early_data_mgr.accept_early_data(&client_id));
    
    let stats = early_data_mgr.stats();
    assert_eq!(stats.stored_identities, 1);
    assert_eq!(stats.accepted_count, 1);
}

#[test]
fn test_session_tickets_enhancement_integration() {
    let ticket_mgr = SessionTicketManager::new(3600, 100);
    
    let session_key = b"master_secret_key".to_vec();
    let client_identity = b"client_cert_fingerprint".to_vec();
    
    let ticket_id = ticket_mgr.create_ticket(session_key.clone(), client_identity);
    assert!(!ticket_id.is_empty());
    
    let reused = ticket_mgr.reuse_ticket(&ticket_id);
    assert!(reused.is_some());
    assert_eq!(reused.unwrap().reuse_count, 1);
    
    let reused2 = ticket_mgr.reuse_ticket(&ticket_id);
    assert_eq!(reused2.unwrap().reuse_count, 2);
    
    let stats = ticket_mgr.stats();
    assert_eq!(stats.total_tickets, 1);
    assert_eq!(stats.reused_count, 2);
}

#[test]
fn test_connection_pooling_integration() {
    let pool = ConnectionPool::new(100, 3600);
    
    let peer1 = b"192.168.1.100:443".to_vec();
    let peer2 = b"192.168.1.101:443".to_vec();
    
    let conn1_id = pool.add_connection(peer1.clone());
    let _conn2_id = pool.add_connection(peer2.clone());
    
    let found = pool.find_connection(&peer1);
    assert_eq!(found, Some(conn1_id));
    
    let conn1 = pool.get_connection(conn1_id);
    assert!(conn1.is_some());
    assert_eq!(conn1.unwrap().bytes_sent, 0);
    
    assert!(pool.record_traffic(conn1_id, 5000, 10000));
    
    let stats = pool.stats();
    assert_eq!(stats.total_connections, 2);
}

#[test]
fn test_handshake_optimization_integration() {
    let optimizer = HandshakeOptimizer::new(3600, 100);
    
    let peer = b"192.168.1.50:443".to_vec();
    let dh_params = b"dh_prime_group14".to_vec();
    let ecdh_curve = b"prime256v1".to_vec();
    let cipher_suite = b"TLS_ECDHE_RSA_WITH_AES_256_GCM".to_vec();
    
    optimizer.cache_params(peer.clone(), dh_params.clone(), ecdh_curve.clone(), cipher_suite);
    
    let cached = optimizer.get_params(&peer);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().dh_params, dh_params);
    
    let stats = optimizer.stats();
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.hit_rate_percent, 100);
}

#[test]
fn test_record_batching_integration() {
    let batcher = RecordBatcher::new(16384, 100);
    
    let record1 = b"TLS Record 1".to_vec();
    let record2 = b"TLS Record 2".to_vec();
    let record3 = b"TLS Record 3".to_vec();
    
    assert!(batcher.add_record(record1));
    assert!(batcher.add_record(record2));
    assert_eq!(batcher.get_record_count(), 2);
    
    assert!(batcher.add_record(record3));
    assert_eq!(batcher.get_record_count(), 3);
    
    let flushed = batcher.force_flush();
    assert!(flushed.is_some());
    assert_eq!(flushed.unwrap().len(), 3 * 12);
    assert_eq!(batcher.get_record_count(), 0);
}

#[test]
fn test_memory_pool_integration() {
    let config = PoolConfig {
        block_size: 1024,
        block_count: 8,
    };
    let mem_pool = MemoryPool::new(config);
    
    let block_id = mem_pool.allocate();
    assert!(block_id.is_some());
    let work_buf = block_id;
    
    let data = b"Important TLS data";
    assert!(mem_pool.write_block(work_buf.unwrap(), data));
    
    let stats = mem_pool.stats();
    assert_eq!(stats.allocated_blocks, 1);
    assert!(stats.free_blocks >= 7);
    
    assert!(mem_pool.deallocate(work_buf.unwrap()));
}

#[test]
fn test_all_features_combined_integration() {
    let early_data = EarlyDataManager::new(8192, 3600);
    let tickets = SessionTicketManager::new(3600, 100);
    let pool = ConnectionPool::new(50, 3600);
    let optimizer = HandshakeOptimizer::new(3600, 50);
    let batcher = RecordBatcher::new(16384, 100);
    let mem_pool = MemoryPool::new(PoolConfig {
        block_size: 2048,
        block_count: 16,
    });
    
    let client_id = b"client_premium".to_vec();
    let peer_addr = b"10.0.0.1:443".to_vec();
    let ticket_key = b"session_secret".to_vec();
    
    let early_payload = b"ClientHello with early data".to_vec();
    early_data.store_early_data(client_id.clone(), early_payload);
    
    let ticket_id = tickets.create_ticket(ticket_key, client_id.clone());
    
    let conn_id = pool.add_connection(peer_addr.clone());
    
    let dh = b"dh_params".to_vec();
    let ecdh = b"ecdh_curve".to_vec();
    let cipher = b"TLS_ECDHE_RSA_WITH_AES_256_GCM".to_vec();
    optimizer.cache_params(peer_addr.clone(), dh, ecdh, cipher);
    
    let rec1 = b"Record1".to_vec();
    let rec2 = b"Record2".to_vec();
    batcher.add_record(rec1);
    batcher.add_record(rec2);
    
    let work_buf = mem_pool.allocate();
    if let Some(buf_id) = work_buf {
        let _ = mem_pool.write_block(buf_id, b"Session data");
    }
    
    assert!(early_data.has_early_data(&client_id));
    assert!(tickets.has_valid_ticket(&ticket_id));
    assert_eq!(pool.find_connection(&peer_addr), Some(conn_id));
    assert!(optimizer.has_cached_params(&peer_addr));
    assert_eq!(batcher.get_record_count(), 2);
    assert!(mem_pool.is_allocated(work_buf.unwrap()));
    
    println!("✅ All 6 performance optimization features working together!");
}
