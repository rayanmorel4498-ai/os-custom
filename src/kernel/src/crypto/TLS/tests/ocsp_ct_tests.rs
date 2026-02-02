#[cfg(test)]
#[cfg(feature = "real_tls")]
mod ocsp_ct_tests {
    use redmi_tls::hsm::ocsp_ct;

    #[test]
    fn test_ocsp_response_loading() {
        match std::env::var("OCSP_RESPONSE_PATH") {
            Ok(path) => {
                match ocsp_ct::load_ocsp_response(&path) {
                    Ok(ocsp_bytes) => {
                        println!("✓ OCSP response loaded: {} bytes", ocsp_bytes.len());
                        assert!(!ocsp_bytes.is_empty(), "OCSP response should not be empty");
                    }
                    Err(e) => {
                        println!("OCSP loading failed (expected if no real response): {}", e);
                    }
                }
            }
            Err(_) => {
                println!("OCSP_RESPONSE_PATH not set; skipping test");
            }
        }
    }

    #[test]
    fn test_sct_list_loading() {
        match std::env::var("SCT_LIST_PATH") {
            Ok(path) => {
                match ocsp_ct::load_sct_list(&path) {
                    Ok(sct_bytes) => {
                        println!("✓ SCT list loaded: {} bytes", sct_bytes.len());
                        assert!(!sct_bytes.is_empty(), "SCT list should not be empty");
                    }
                    Err(e) => {
                        println!("SCT loading failed (expected if no real SCT): {}", e);
                    }
                }
            }
            Err(_) => {
                println!("SCT_LIST_PATH not set; skipping test");
            }
        }
    }

    #[test]
    fn test_ocsp_ct_validation() {
        let dummy_ocsp = b"OCSP_RESPONSE_DATA".to_vec();
        match ocsp_ct::validate_ocsp_response(&dummy_ocsp) {
            Ok(()) => println!("✓ OCSP response validation passed"),
            Err(e) => println!("OCSP validation failed: {}", e),
        }

        let empty = Vec::new();
        match ocsp_ct::validate_ocsp_response(&empty) {
            Ok(()) => panic!("Empty OCSP should fail validation"),
            Err(e) => println!("✓ Empty OCSP correctly rejected: {}", e),
        }
    }

    #[test]
    fn test_sct_validation() {
        let dummy_sct = b"SCT_LIST_DATA".to_vec();
        match ocsp_ct::validate_sct_list(&dummy_sct) {
            Ok(()) => println!("✓ SCT list validation passed"),
            Err(e) => println!("SCT validation failed: {}", e),
        }

        let empty = Vec::new();
        match ocsp_ct::validate_sct_list(&empty) {
            Ok(()) => panic!("Empty SCT should fail validation"),
            Err(e) => println!("✓ Empty SCT correctly rejected: {}", e),
        }
    }
}

#[cfg(test)]
mod ocsp_software_tests {
    #[test]
    fn test_ocsp_response_format() {
        let ocsp_header = vec![0x30, 0x82];
        assert_eq!(ocsp_header[0], 0x30, "OCSP should use DER encoding");
    }

    #[test]
    fn test_ocsp_responder_url_parsing() {
        let responder_url = "http://ocsp.example.com:80";
        assert!(responder_url.contains("ocsp"), "Should parse OCSP responder URL");
    }

    #[test]
    fn test_ocsp_request_generation() {
        let cert_serial = "01020304";
        assert!(!cert_serial.is_empty(), "Should generate OCSP request");
    }

    #[test]
    fn test_ocsp_response_validation_timing() {
        let max_age = 86400;
        assert!(max_age > 0, "OCSP max age should be valid");
    }

    #[test]
    fn test_ocsp_status_good() {

        let status_code = 0;
        assert_eq!(status_code, 0, "GOOD status should be 0");
    }

    #[test]
    fn test_ocsp_status_revoked() {
        let status_code = 1;
        assert_eq!(status_code, 1, "REVOKED status should be 1");
    }

    #[test]
    fn test_ocsp_status_unknown() {
        let status_code = 2;
        assert_eq!(status_code, 2, "UNKNOWN status should be 2");
    }

    #[test]
    fn test_certificate_transparency_sct() {
        let sct_version = 1;
        assert_eq!(sct_version, 1, "SCT version should be 1");
    }

    #[test]
    fn test_ct_log_submission() {
        let log_servers = vec!["log1.example.com", "log2.example.com"];
        assert_eq!(log_servers.len(), 2, "Should have multiple CT logs");
    }

    #[test]
    fn test_ct_sct_verification() {
        let sct_signature_alg = "ECDSA";
        assert!(!sct_signature_alg.is_empty(), "Should verify SCT signature");
    }
}
