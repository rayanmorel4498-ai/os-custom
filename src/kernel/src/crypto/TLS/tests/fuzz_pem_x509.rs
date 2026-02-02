#[cfg(test)]
mod fuzz {
    use rand::Rng;
    use rustls_pemfile::certs;
    use x509_parser::parse_x509_certificate;

    #[test]
    fn fuzz_pem_and_x509_no_panic() {
        let mut rng = rand::thread_rng();
        let mut valid_count = 0;
        let mut parse_count = 0;
        
        for _ in 0..1000 {
            let len: usize = rng.gen_range(1..512);
            let mut data = vec![0u8; len];
            rng.fill(&mut data[..]);
            
            let cert_result = certs(&mut std::io::Cursor::new(&data));
            let x509_result = parse_x509_certificate(&data);
            
            if cert_result.is_ok() {
                valid_count += 1;
            }
            if x509_result.is_ok() {
                parse_count += 1;
            }
        }
        
        assert!(valid_count >= 0, "Should attempt parsing");
        assert!(parse_count >= 0, "Should attempt X509 parsing");
    }

    #[test]
    fn fuzz_empty_and_minimal_data() {
        let empty = b"";
        let _ = certs(&mut std::io::Cursor::new(empty));
        let _ = parse_x509_certificate(empty);
        
        let single_byte = b"X";
        let _ = certs(&mut std::io::Cursor::new(single_byte));
        let _ = parse_x509_certificate(single_byte);
    }

    #[test]
    fn fuzz_pem_boundaries() {
        let partial_pem = b"-----BEGIN CERTIFICATE";
        let _ = certs(&mut std::io::Cursor::new(partial_pem));
        let _ = parse_x509_certificate(partial_pem);
        
        let malformed = b"-----BEGIN CERT-----\ninvalid\n-----END CERT-----";
        let _ = certs(&mut std::io::Cursor::new(malformed));
        let _ = parse_x509_certificate(malformed);
    }

    #[test]
    fn fuzz_large_inputs() {
        let mut rng = rand::thread_rng();
        
        for size in [1024, 4096, 16384, 65536].iter() {
            let mut data = vec![0u8; *size];
            rng.fill(&mut data[..]);
            let _ = certs(&mut std::io::Cursor::new(&data));
            let _ = parse_x509_certificate(&data);
        }
    }
}
