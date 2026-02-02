#[cfg(test)]
mod component_token_tests {
    use redmi_tls::{ComponentTokenManager, ComponentType};

    #[test]
    fn test_issue_and_validate_token() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::CPU, 0, 3600)
            .expect("Failed to issue token");

        assert_eq!(token.component, ComponentType::CPU);
        assert_eq!(token.instance_id, 0);
        assert!(!token.token_value.is_empty());
        assert!(!token.public_key.is_empty());
        assert!(token.expires_at > token.created_at);
    }

    #[test]
    fn test_validate_token_success() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::GPU, 1, 3600)
            .expect("Failed to issue token");

        let is_valid = mgr
            .validate_token(&token.token_id, &token.token_value)
            .expect("Failed to validate token");

        assert!(is_valid, "Token should be valid");
    }

    #[test]
    fn test_validate_token_wrong_value() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::RAM, 0, 3600)
            .expect("Failed to issue token");

        let is_valid = mgr
            .validate_token(&token.token_id, "wrong_token_value")
            .expect("Validate should return result");

        assert!(!is_valid, "Invalid token should not validate");
    }

    #[test]
    fn test_sign_and_verify_signature() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::IA, 0, 3600)
            .expect("Failed to issue token");

        let signature = mgr
            .sign_action(&token.token_id, "approve_camera_access", "nonce_123")
            .expect("Failed to sign action");

        assert_eq!(signature.message, "approve_camera_access");
        assert!(!signature.signature.is_empty());

        let is_valid = mgr
            .verify_signature(&signature)
            .expect("Failed to verify signature");

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_verify_tampered_signature() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::Thermal, 0, 3600)
            .expect("Failed to issue token");

        let mut signature = mgr
            .sign_action(&token.token_id, "throttle_cpu", "nonce_456")
            .expect("Failed to sign action");

        signature.signature = "tampered_signature_xyz".to_string();

        let result = mgr.verify_signature(&signature);
        assert!(result.is_err(), "Tampered signature should fail verification");
    }

    #[test]
    fn test_revoke_token() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::Modem, 0, 3600)
            .expect("Failed to issue token");

        let valid_before = mgr
            .validate_token(&token.token_id, &token.token_value)
            .expect("Failed to validate");
        assert!(valid_before);

        mgr.revoke_token(&token.token_id)
            .expect("Failed to revoke token");

        let result = mgr.validate_token(&token.token_id, &token.token_value);
        assert!(result.is_err(), "Revoked token should not validate");
    }

    #[test]
    fn test_multiple_components_different_tokens() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let cpu_token = mgr
            .issue_session_token(ComponentType::CPU, 0, 3600)
            .expect("Failed CPU token");
        
        let gpu_token = mgr
            .issue_session_token(ComponentType::GPU, 0, 3600)
            .expect("Failed GPU token");
        
        let ia_token = mgr
            .issue_session_token(ComponentType::IA, 0, 3600)
            .expect("Failed IA token");

        assert_ne!(cpu_token.token_id, gpu_token.token_id);
        assert_ne!(cpu_token.token_id, ia_token.token_id);
        assert_ne!(gpu_token.token_id, ia_token.token_id);

        assert_ne!(cpu_token.token_value, gpu_token.token_value);
        assert_ne!(cpu_token.public_key, gpu_token.public_key);

        assert!(mgr.validate_token(&cpu_token.token_id, &cpu_token.token_value)
            .expect("CPU validation failed"));
        assert!(mgr.validate_token(&gpu_token.token_id, &gpu_token.token_value)
            .expect("GPU validation failed"));
        assert!(mgr.validate_token(&ia_token.token_id, &ia_token.token_value)
            .expect("IA validation failed"));
    }

    #[test]
    fn test_nonce_in_signature() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::Display, 0, 3600)
            .expect("Failed to issue token");

        let sig1 = mgr
            .sign_action(&token.token_id, "render_frame", "nonce_1")
            .expect("Failed to sign");
        
        let sig2 = mgr
            .sign_action(&token.token_id, "render_frame", "nonce_2")
            .expect("Failed to sign");

        assert_ne!(sig1.signature, sig2.signature);
        assert_ne!(sig1.nonce, sig2.nonce);
    }

    #[test]
    fn test_signature_with_wrong_nonce() {
        let mgr = ComponentTokenManager::new("test_master_key_32_bytes_long");
        
        let token = mgr
            .issue_session_token(ComponentType::Audio, 0, 3600)
            .expect("Failed to issue token");

        let mut signature = mgr
            .sign_action(&token.token_id, "play_sound", "correct_nonce")
            .expect("Failed to sign");

        signature.nonce = "wrong_nonce".to_string();

        let result = mgr.verify_signature(&signature);
        assert!(result.is_err(), "Signature with wrong nonce should fail");
    }
}

#[cfg(test)]
mod session_manager_tests {
    use redmi_tls::{ComponentType, SessionManager};

    #[test]
    fn test_open_and_close_session() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        let session = mgr
            .open_session(ComponentType::CPU, 0, None)
            .expect("Failed to open session");

        assert_eq!(session.token.component, ComponentType::CPU);
        assert_eq!(session.token.instance_id, 0);
        assert_eq!(session.valid_requests, 0);
        assert_eq!(session.failed_requests, 0);

        let retrieved = mgr
            .get_session(ComponentType::CPU, 0)
            .expect("Failed to get session");
        assert_eq!(retrieved.token.token_id, session.token.token_id);

        mgr.close_session(ComponentType::CPU, 0)
            .expect("Failed to close session");

        let result = mgr.get_session(ComponentType::CPU, 0);
        assert!(result.is_err(), "Closed session should not exist");
    }

    #[test]
    fn test_heartbeat_updates_timestamp() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        mgr.open_session(ComponentType::GPU, 0, None)
            .expect("Failed to open session");

        let session_before = mgr
            .get_session(ComponentType::GPU, 0)
            .expect("Failed to get session");
        let ts_before = session_before.last_heartbeat;

        std::thread::sleep(std::time::Duration::from_millis(10));

        mgr.heartbeat(ComponentType::GPU, 0)
            .expect("Failed heartbeat");

        let session_after = mgr
            .get_session(ComponentType::GPU, 0)
            .expect("Failed to get session");
        let ts_after = session_after.last_heartbeat;

        assert!(ts_after >= ts_before, "Heartbeat should update timestamp");
    }

    #[test]
    fn test_record_request_stats() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        mgr.open_session(ComponentType::RAM, 0, None)
            .expect("Failed to open session");

        mgr.record_request(ComponentType::RAM, 0, true)
            .expect("Failed to record success");
        mgr.record_request(ComponentType::RAM, 0, true)
            .expect("Failed to record success");
        mgr.record_request(ComponentType::RAM, 0, false)
            .expect("Failed to record failure");

        let session = mgr
            .get_session(ComponentType::RAM, 0)
            .expect("Failed to get session");

        assert_eq!(session.valid_requests, 2);
        assert_eq!(session.failed_requests, 1);
    }

    #[test]
    fn test_rotate_token_in_session() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        let session1 = mgr
            .open_session(ComponentType::Thermal, 0, None)
            .expect("Failed to open session");

        let old_token_id = session1.token.token_id.clone();

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let new_token = mgr
            .rotate_token(ComponentType::Thermal, 0)
            .expect("Failed to rotate token");

        assert_ne!(new_token.token_id, old_token_id);

        let session2 = mgr
            .get_session(ComponentType::Thermal, 0)
            .expect("Failed to get session after rotate");

        assert_eq!(session2.token.token_id, new_token.token_id);
    }

    #[test]
    fn test_list_sessions() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        mgr.open_session(ComponentType::CPU, 0, None)
            .expect("Failed CPU");
        mgr.open_session(ComponentType::GPU, 0, None)
            .expect("Failed GPU");
        mgr.open_session(ComponentType::IA, 0, None)
            .expect("Failed IA");

        let sessions = mgr.list_sessions();
        assert_eq!(sessions.len(), 3, "Should have 3 sessions");

        let keys: Vec<String> = sessions.iter().map(|(k, _)| k.clone()).collect();
        assert!(keys.iter().any(|k| k.contains("cpu")));
        assert!(keys.iter().any(|k| k.contains("gpu")));
        assert!(keys.iter().any(|k| k.contains("ia")));
    }

    #[test]
    fn test_cleanup_expired_sessions() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 1, 1);
        
        mgr.open_session(ComponentType::Modem, 0, None)
            .expect("Failed to open");

        redmi_tls::time_abstraction::kernel_time_advance(2);

        let removed = mgr.cleanup_expired();
        assert_eq!(removed, 1, "Should have removed 1 expired session");

        let result = mgr.get_session(ComponentType::Modem, 0);
        assert!(result.is_err(), "Expired session should be gone");
    }

    #[test]
    fn test_session_stats() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        mgr.open_session(ComponentType::Display, 0, None)
            .expect("Failed to open");

        mgr.record_request(ComponentType::Display, 0, true)
            .expect("Failed to record");
        mgr.record_request(ComponentType::Display, 0, true)
            .expect("Failed to record");

        let stats = mgr
            .session_stats(ComponentType::Display, 0)
            .expect("Failed to get stats");

        assert_eq!(stats.component, "display");
        assert_eq!(stats.valid_requests, 2);
        assert_eq!(stats.failed_requests, 0);
    }

    #[test]
    fn test_multiple_instances_same_component() {
        let mgr = SessionManager::new("test_master_key_32_bytes_long", 300, 600);
        
        let session0 = mgr
            .open_session(ComponentType::FrontCamera, 0, None)
            .expect("Failed camera 0");
        
        let session1 = mgr
            .open_session(ComponentType::FrontCamera, 1, None)
            .expect("Failed camera 1");

        assert_ne!(session0.token.token_id, session1.token.token_id);

        let retrieved0 = mgr
            .get_session(ComponentType::FrontCamera, 0)
            .expect("Failed to get camera 0");
        let retrieved1 = mgr
            .get_session(ComponentType::FrontCamera, 1)
            .expect("Failed to get camera 1");

        assert_eq!(retrieved0.token.instance_id, 0);
        assert_eq!(retrieved1.token.instance_id, 1);
    }
}

#[cfg(test)]
mod component_api_tests {
    use redmi_tls::{
        ComponentAPIHandler, IssueTokenRequest, OpenSessionRequest, SignActionRequest,
        HeartbeatRequest, ValidateTokenRequest, VerifySignatureRequest, RotateTokenRequest,
    };

    #[test]
    fn test_api_issue_token() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let req = IssueTokenRequest {
            component: "cpu".to_string(),
            instance_id: 0,
            valid_for_secs: 3600,
        };

        let res = api.issue_token(req).expect("Failed to issue token");
        assert!(!res.token_id.is_empty());
        assert!(!res.token_value.is_empty());
        assert!(!res.public_key.is_empty());
    }

    #[test]
    fn test_api_validate_token() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let issue_req = IssueTokenRequest {
            component: "gpu".to_string(),
            instance_id: 0,
            valid_for_secs: 3600,
        };
        let token_res = api.issue_token(issue_req).expect("Failed to issue");

        let validate_req = ValidateTokenRequest {
            token_id: token_res.token_id,
            token_value: token_res.token_value,
        };

        let is_valid = api
            .validate_token(validate_req)
            .expect("Failed to validate");
        assert!(is_valid);
    }

    #[test]
    fn test_api_open_session() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let req = OpenSessionRequest {
            component: "ia".to_string(),
            instance_id: 0,
        };

        let res = api.open_session(req).expect("Failed to open session");
        assert!(!res.token_id.is_empty());
        assert!(!res.token_value.is_empty());
    }

    #[test]
    fn test_api_sign_action() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "thermal".to_string(),
            instance_id: 0,
        };
        let session = api.open_session(open_req).expect("Failed to open");

        let sign_req = SignActionRequest {
            token_id: session.token_id,
            message: "throttle_cpu".to_string(),
            nonce: "nonce_xyz".to_string(),
        };

        let sig = api.sign_action(sign_req).expect("Failed to sign");
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn test_api_verify_signature() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "modem".to_string(),
            instance_id: 0,
        };
        let session = api.open_session(open_req).expect("Failed to open");

        let sign_req = SignActionRequest {
            token_id: session.token_id.clone(),
            message: "send_sms".to_string(),
            nonce: "nonce_123".to_string(),
        };
        let sig = api.sign_action(sign_req).expect("Failed to sign");

        let verify_req = VerifySignatureRequest {
            token_id: sig.token_id,
            message: sig.message,
            signature: sig.signature,
            signed_at: sig.signed_at,
            nonce: "nonce_123".to_string(),
        };

        let valid = api
            .verify_signature(verify_req)
            .expect("Failed to verify");
        assert!(valid);
    }

    #[test]
    fn test_api_heartbeat() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "display".to_string(),
            instance_id: 0,
        };
        api.open_session(open_req).expect("Failed to open");

        let hb_req = HeartbeatRequest {
            component: "display".to_string(),
            instance_id: 0,
        };

        let result = api.heartbeat(hb_req);
        assert!(result.is_ok(), "Heartbeat should succeed");
    }

    #[test]
    fn test_api_rotate_token() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "audio".to_string(),
            instance_id: 0,
        };
        let session = api.open_session(open_req).expect("Failed to open");

        let rotate_req = RotateTokenRequest {
            component: "audio".to_string(),
            instance_id: 0,
        };

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let new_token = api.rotate_token(rotate_req).expect("Failed to rotate");
        assert_ne!(new_token.token_id, session.token_id);
        assert_ne!(new_token.token_value, session.token_value);
    }

    #[test]
    fn test_api_close_session() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "haptics".to_string(),
            instance_id: 0,
        };
        api.open_session(open_req).expect("Failed to open");

        let result = api.close_session("haptics".to_string(), 0);
        assert!(result.is_ok(), "Close session should succeed");
    }

    #[test]
    fn test_api_list_sessions() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let req1 = OpenSessionRequest {
            component: "cpu".to_string(),
            instance_id: 0,
        };
        let req2 = OpenSessionRequest {
            component: "gpu".to_string(),
            instance_id: 0,
        };

        api.open_session(req1).expect("Failed CPU");
        api.open_session(req2).expect("Failed GPU");

        let sessions = api.list_sessions().expect("Failed to list");
        assert!(sessions.is_array());
        assert_eq!(sessions.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_api_session_stats() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let open_req = OpenSessionRequest {
            component: "biometric".to_string(),
            instance_id: 0,
        };
        api.open_session(open_req).expect("Failed to open");

        let stats = api
            .session_stats("biometric".to_string(), 0)
            .expect("Failed to get stats");

        assert!(stats.is_object());
        assert!(stats.get("component").is_some());
    }

    #[test]
    fn test_api_invalid_component() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let req = IssueTokenRequest {
            component: "invalid_component".to_string(),
            instance_id: 0,
            valid_for_secs: 3600,
        };

        let result = api.issue_token(req);
        assert!(result.is_err(), "Invalid component should return error");
    }

    #[test]
    fn test_api_all_components() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let components = vec![
            "kernel", "cpu", "gpu", "ram", "thermal",
            "os", "ia", "identity", "permissions",
            "network", "firewall", "messaging", "calling",
            "location", "anti_theft", "front_camera", "rear_camera",
            "gps", "nfc", "modem", "display", "audio", "haptics",
            "biometric", "power",
        ];

        for comp_name in components {
            let req = IssueTokenRequest {
                component: comp_name.to_string(),
                instance_id: 0,
                valid_for_secs: 3600,
            };

            let result = api.issue_token(req);
            assert!(
                result.is_ok(),
                "Component {} should be supported",
                comp_name
            );
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use redmi_tls::{OpenSessionRequest, SignActionRequest, VerifySignatureRequest, HeartbeatRequest, RotateTokenRequest, ComponentAPIHandler};

    #[test]
    fn test_full_workflow() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let cpu_session = api
            .open_session(OpenSessionRequest {
                component: "cpu".to_string(),
                instance_id: 0,
            })
            .expect("CPU open failed");

        let gpu_session = api
            .open_session(OpenSessionRequest {
                component: "gpu".to_string(),
                instance_id: 0,
            })
            .expect("GPU open failed");

        let cpu_sig = api
            .sign_action(SignActionRequest {
                token_id: cpu_session.token_id.clone(),
                message: "access_memory".to_string(),
                nonce: "cpu_nonce_1".to_string(),
            })
            .expect("CPU sign failed");

        let cpu_valid = api
            .verify_signature(VerifySignatureRequest {
                token_id: cpu_sig.token_id,
                message: cpu_sig.message,
                signature: cpu_sig.signature,
                signed_at: cpu_sig.signed_at,
                nonce: "cpu_nonce_1".to_string(),
            })
            .expect("CPU verify failed");
        assert!(cpu_valid);

        let gpu_sig = api
            .sign_action(SignActionRequest {
                token_id: gpu_session.token_id.clone(),
                message: "render_frame".to_string(),
                nonce: "gpu_nonce_1".to_string(),
            })
            .expect("GPU sign failed");

        let gpu_valid = api
            .verify_signature(VerifySignatureRequest {
                token_id: gpu_sig.token_id,
                message: gpu_sig.message,
                signature: gpu_sig.signature,
                signed_at: gpu_sig.signed_at,
                nonce: "gpu_nonce_1".to_string(),
            })
            .expect("GPU verify failed");
        assert!(gpu_valid);

        api.heartbeat(HeartbeatRequest {
            component: "cpu".to_string(),
            instance_id: 0,
        })
        .expect("CPU heartbeat failed");

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let new_cpu_token = api
            .rotate_token(RotateTokenRequest {
                component: "cpu".to_string(),
                instance_id: 0,
            })
            .expect("CPU rotate failed");

        assert_ne!(new_cpu_token.token_id, cpu_session.token_id);

        let sessions = api.list_sessions().expect("List failed");
        assert_eq!(sessions.as_array().unwrap().len(), 2);

        api.close_session("cpu".to_string(), 0)
            .expect("CPU close failed");
        api.close_session("gpu".to_string(), 0)
            .expect("GPU close failed");

        let final_sessions = api.list_sessions().expect("Final list failed");
        assert_eq!(final_sessions.as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_security_workflow() {
        let api = ComponentAPIHandler::new("test_master_key_32_bytes_long", 300, 600);
        
        let ia_session = api
            .open_session(OpenSessionRequest {
                component: "ia".to_string(),
                instance_id: 0,
            })
            .expect("IA open failed");

        let modem_session = api
            .open_session(OpenSessionRequest {
                component: "modem".to_string(),
                instance_id: 0,
            })
            .expect("Modem open failed");

        let approval = api
            .sign_action(SignActionRequest {
                token_id: ia_session.token_id.clone(),
                message: "approve_modem_camera_access".to_string(),
                nonce: "approval_1".to_string(),
            })
            .expect("IA approval sign failed");

        let approval_valid = api
            .verify_signature(VerifySignatureRequest {
                token_id: approval.token_id,
                message: approval.message,
                signature: approval.signature,
                signed_at: approval.signed_at,
                nonce: "approval_1".to_string(),
            })
            .expect("Approval verify failed");
        assert!(approval_valid, "IA approval should be valid");

        let modem_action = api
            .sign_action(SignActionRequest {
                token_id: modem_session.token_id.clone(),
                message: "take_photo".to_string(),
                nonce: "modem_action_1".to_string(),
            })
            .expect("Modem action sign failed");

        let modem_valid = api
            .verify_signature(VerifySignatureRequest {
                token_id: modem_action.token_id,
                message: modem_action.message,
                signature: modem_action.signature,
                signed_at: modem_action.signed_at,
                nonce: "modem_action_1".to_string(),
            })
            .expect("Modem verify failed");
        assert!(modem_valid, "Modem action should be valid");
    }
}
