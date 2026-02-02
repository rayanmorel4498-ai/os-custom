#[cfg(test)]
mod external_tests {
    use std::sync::Arc;
    use std::sync::Arc as AllocArc;
    use crossbeam_queue::SegQueue;

    #[test]
    fn exercise_external_loop_registration() {
        let master = "master-for-external";
        let ck = Arc::new(redmi_tls::crypto::CryptoKey::new(master, "ext").expect("crypto key"));
        let tm = Arc::new(redmi_tls::TokenManager::new(master, "other"));
        let hp = Arc::new(redmi_tls::honeypot::HoneypotSystem::new(tm.clone()).expect("honeypot new"));

        let sm = Arc::new(redmi_tls::session_manager::SessionManager::new(master, 300, 600));
        let _n = sm.open_session(redmi_tls::ComponentType::Network, 0, None).unwrap();
        let _m = sm.open_session(redmi_tls::ComponentType::Messaging, 0, None).unwrap();
        let _c = sm.open_session(redmi_tls::ComponentType::Calling, 0, None).unwrap();

        let el = Arc::new(redmi_tls::external_loop::ExternalLoop::new(sm.clone(), ck.clone(), hp.clone()));

        let tx_a = AllocArc::new(SegQueue::new());
        let tx_b = AllocArc::new(SegQueue::new());

        el.register_node("net_node", tx_a.clone());
        el.register_node("sms_node", tx_b.clone());

        let nodes = el.list_nodes();
        assert!(nodes.contains(&"net_node".to_string()));
        assert!(nodes.contains(&"sms_node".to_string()));
    }
}
