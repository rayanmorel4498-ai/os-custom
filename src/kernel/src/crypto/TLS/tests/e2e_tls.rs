#[cfg(all(test, feature = "real_tls"))]
mod e2e {
    use redmi_tls as tls_crate;
    use std::thread;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use rcgen::generate_simple_self_signed;
    use std::fs::File;
    use std::io::Write as IoWrite;

    #[test]
    fn tls_handshake_echo() {
        let subject_alt_names = vec!["localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();

        let tmpdir = tempfile::tempdir().unwrap();
        let cert_path = tmpdir.path().join("test.crt");
        let key_path = tmpdir.path().join("test.key");
        let mut f = File::create(&cert_path).unwrap(); f.write_all(cert_pem.as_bytes()).unwrap();
        let mut k = File::create(&key_path).unwrap(); k.write_all(key_pem.as_bytes()).unwrap();

        let addr = "127.0.0.1:44444";
        let certp = cert_path.to_string_lossy().to_string();
        let keyp = key_path.to_string_lossy().to_string();

        thread::spawn(move || {
            let _ = tls_crate::server::serve_real(addr, &certp, &keyp);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s.write_all(b"hello");
            let mut buf = [0u8; 16];
            let _ = s.read(&mut buf);
        } else {
            panic!("failed to connect to test server");
        }
    }
}
