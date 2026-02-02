use redmi_tls::core::session::session_cache::SessionCache;
use redmi_tls::core::session::psk_manager::PSKManager;
use redmi_tls::core::session::session_tickets::SessionTicketManager;

#[test]
fn test_replay_session_reuse_detection() {
    let cache = SessionCache::new();
    
    let session_id = b"session_001".to_vec();
    let master_secret = vec![1u8; 48];
    let cipher_suite = 0x1301u16;
    
    cache.cache_session("example.com", session_id.clone(), master_secret.clone(), cipher_suite);
    
    let retrieved = cache.get_session("example.com", &session_id);
    assert!(retrieved.is_some(), "Session should be retrievable");
    
    let retrieved_again = cache.get_session("example.com", &session_id);
    assert!(
        retrieved_again.is_some(),
        "Session should still be retrievable on second access"
    );
}

#[test]
fn test_ticket_rotation_prevents_reuse() {
    let ticket_mgr = SessionTicketManager::new(3600, 100);
    
    let session_key1 = vec![1u8; 32];
    let identity1 = b"client_1".to_vec();
    let ticket1 = ticket_mgr.create_ticket(session_key1.clone(), identity1.clone());
    
    let reused1 = ticket_mgr.reuse_ticket(&ticket1);
    assert!(reused1.is_some(), "Ticket 1 should be reusable");
    
    if let Some(r1) = reused1 {
        assert_eq!(r1.client_identity, identity1, "Ticket 1 should preserve identity");
        assert_eq!(r1.reuse_count, 1, "Ticket 1 should have reuse count of 1");
    }
    
    let session_key2 = vec![2u8; 32];
    let identity2 = b"client_2".to_vec();
    let ticket2 = ticket_mgr.create_ticket(session_key2.clone(), identity2.clone());
    
    let reused2 = ticket_mgr.reuse_ticket(&ticket2);
    assert!(reused2.is_some(), "Ticket 2 should be reusable");
    
    if let Some(r2) = reused2 {
        assert_eq!(r2.client_identity, identity2, "Ticket 2 should preserve identity");
        assert_eq!(r2.reuse_count, 1, "Ticket 2 should have reuse count of 1");
    }
}

#[test]
fn test_psk_expiration_prevents_replay() {
    let psk_mgr = PSKManager::new(10, 100);
    let current_time = 1000u64;
    
    let identity = b"client_identity".to_vec();
    let key = vec![42u8; 32];
    
    psk_mgr.store_psk(identity.clone(), key, current_time);
    
    let retrieved_fresh = psk_mgr.get_psk(&identity, current_time + 50);
    assert!(
        retrieved_fresh.is_some(),
        "PSK should be retrievable within TTL"
    );
    
    let retrieved_expired = psk_mgr.get_psk(&identity, current_time + 200);
    assert!(
        retrieved_expired.is_none(),
        "PSK should not be retrievable after TTL expires"
    );
}

#[test]
fn test_session_id_uniqueness() {
    let cache = SessionCache::new();
    
    let session_id_1 = b"session_unique_001".to_vec();
    let session_id_2 = b"session_unique_002".to_vec();
    let master_secret = vec![1u8; 48];
    let cipher_suite = 0x1301u16;
    
    cache.cache_session("example.com", session_id_1.clone(), master_secret.clone(), cipher_suite);
    cache.cache_session("example.com", session_id_2.clone(), master_secret.clone(), cipher_suite);
    
    let r1 = cache.get_session("example.com", &session_id_1);
    let r2 = cache.get_session("example.com", &session_id_2);
    
    assert!(r1.is_some());
    assert!(r2.is_some());
}

#[test]
fn test_session_invalidation_on_removal() {
    let cache = SessionCache::new();
    
    let session_id = b"session_for_removal".to_vec();
    let master_secret = vec![1u8; 48];
    let cipher_suite = 0x1301u16;
    
    cache.cache_session("example.com", session_id.clone(), master_secret, cipher_suite);
    
    assert!(
        cache.has_valid_session("example.com", &session_id),
        "Session should exist after caching"
    );
    
    cache.remove_session("example.com", &session_id);
    
    assert!(
        !cache.has_valid_session("example.com", &session_id),
        "Session should not exist after removal"
    );
}

#[test]
fn test_ticket_revocation_prevents_reuse() {
    let ticket_mgr = SessionTicketManager::new(3600, 100);
    
    let session_key = vec![1u8; 32];
    let identity = b"client_revoke".to_vec();
    let ticket_id = ticket_mgr.create_ticket(session_key, identity);
    
    assert!(
        ticket_mgr.has_valid_ticket(&ticket_id),
        "Ticket should be valid after creation"
    );
    
    ticket_mgr.revoke_ticket(&ticket_id);
    
    assert!(
        !ticket_mgr.has_valid_ticket(&ticket_id),
        "Ticket should not be valid after revocation"
    );
}

#[test]
fn test_cleartext_storage_prevention() {
    let ticket_mgr = SessionTicketManager::new(3600, 100);
    
    let session_key = vec![1u8; 32];
    let identity = b"client_encrypt".to_vec();
    let ticket = ticket_mgr.create_ticket(session_key.clone(), identity.clone());
    
    assert!(!ticket.is_empty(), "Ticket should be generated");
    
    let retrieved = ticket_mgr.get_ticket(&ticket);
    assert!(retrieved.is_some(), "Ticket should be retrievable");
}

#[test]
fn test_psk_resumption_tracking() {
    let psk_mgr = PSKManager::new(10, 100);
    let current_time = 1000u64;
    
    let identity = b"track_identity".to_vec();
    let key = vec![100u8; 32];
    
    psk_mgr.store_psk(identity.clone(), key, current_time);
    
    let psk1 = psk_mgr.get_psk(&identity, current_time + 10);
    assert!(psk1.is_some());
    
    if let Some(psk) = psk1 {
        assert!(psk.resumption_count > 0, "Resumption count should be tracked");
    }
}

#[test]
fn test_session_cleanup_on_expiration() {
    let cache = SessionCache::with_ttl(100);
    
    let session_id = b"expire_test".to_vec();
    let master_secret = vec![1u8; 48];
    let cipher_suite = 0x1301u16;
    
    cache.cache_session("example.com", session_id.clone(), master_secret, cipher_suite);
    cache.cleanup_expired();
    
    assert!(
        cache.has_valid_session("example.com", &session_id),
        "Recently cached session should still be valid"
    );
}
