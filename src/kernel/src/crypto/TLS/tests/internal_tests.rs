#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::string::String;
    use crossbeam_queue::SegQueue;
    use redmi_tls::crypto::CryptoKey;
    use redmi_tls::api::token;
    use redmi_tls::session_manager::SessionManager;
    use redmi_tls::primary_loop::{PrimaryLoop, PrimaryChannel};

    #[test]
    fn tokens_generate_and_validate_ok() {
        let master = "super-secret-master";
        let tok = token::generate_token(master, "https_external_v1", 60)
            .expect("generate_token failed");
        assert!(token::validate_token(master, "https_external_v1", &tok));
    }

    #[test]
    fn primary_loop_send_and_recv() {
        let master = "master-for-test";
        let ck = Arc::new(CryptoKey::new(master, "testctx").expect("crypto key"));
        let tm = Arc::new(redmi_tls::TokenManager::new(master, "other"));
        let hp = Arc::new(redmi_tls::honeypot::HoneypotSystem::new(tm.clone()).expect("honeypot new"));

        let sm = Arc::new(SessionManager::new(master, 300, 600));
        let _k = sm.open_session(redmi_tls::ComponentType::Kernel, 0, None).unwrap();

        let il = Arc::new(PrimaryLoop::new(sm.clone(), ck.clone(), hp.clone(), String::from(master)));

        let rx_server = Arc::new(SegQueue::new());
        let _server_ch = PrimaryChannel::new(String::from("server"), il.clone(), rx_server.clone());
        il.register_node("server", rx_server.clone());

        let rx_node = Arc::new(SegQueue::new());
        let _ch1 = PrimaryChannel::new(String::from("node1"), il.clone(), rx_node.clone());
        il.register_node("node1", rx_node.clone());

        let kernel_session = sm.get_session(redmi_tls::ComponentType::Kernel, 0).unwrap();
        let _good_token = kernel_session.token.token_value.clone();

        let payload = b"hello".to_vec();
        let sent = _ch1.send("server", payload.clone(), &_good_token);
        assert!(sent, "send should succeed");

        let got = _server_ch.recv().expect("expected payload");
        assert_eq!(got, payload);
    }
}
