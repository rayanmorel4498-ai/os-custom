extern crate alloc;
use std::time::Instant;

fn main() {
    println!("TLS 1.2 Crypto Components - Performance Benchmarks\n");
    println!("{}", "─".repeat(60));

    println!("\n1. PRF Generation (SHA256):");
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = redmi_tls::core::crypto::PRF::generate(
            b"secret",
            b"label",
            b"seed",
            32,
            redmi_tls::core::crypto::PRFHashAlgorithm::SHA256,
        );
    }
    let duration = start.elapsed();
    println!("   1000 iterations: {:?} ({:.2} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 1000.0
    );

    println!("\n2. Master Secret Derivation:");
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = redmi_tls::core::crypto::MasterSecretDerivation::derive_master_secret(
            &[0x42u8; 48],
            &[0xAAu8; 32],
            &[0xBBu8; 32],
            redmi_tls::core::crypto::PRFHashAlgorithm::SHA256,
        );
    }
    let duration = start.elapsed();
    println!("   1000 iterations: {:?} ({:.2} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 1000.0
    );

    println!("\n3. Cipher Suite Negotiation:");
    let client_suites = vec![
        redmi_tls::core::crypto::CipherSuite::RSA_WITH_AES_128_CBC_SHA,
        redmi_tls::core::crypto::CipherSuite::RSA_WITH_AES_256_CBC_SHA256,
    ];
    let server_prefs = redmi_tls::core::crypto::CipherSuiteNegotiator::default_server_preference();
    
    let start = Instant::now();
    for _ in 0..10000 {
        let _ = redmi_tls::core::crypto::CipherSuiteNegotiator::negotiate(&client_suites, &server_prefs);
    }
    let duration = start.elapsed();
    println!("   10000 iterations: {:?} ({:.3} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 10000.0
    );
n
    println!("\n4. Key Material Derivation:");
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = redmi_tls::core::crypto::SecretDerivationPerSuite::derive_key_material(
            redmi_tls::core::crypto::CipherSuite::RSA_WITH_AES_128_CBC_SHA256,
            &[0x55u8; 48],
            &[0xCCu8; 32],
            &[0xDDu8; 32],
        );
    }
    let duration = start.elapsed();
    println!("   1000 iterations: {:?} ({:.2} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 1000.0
    );

    println!("\n5. RSA Signature Validation (format check):");
    let mut sig = vec![0x00u8; 256];
    sig[0] = 0x00;
    sig[1] = 0x01;
    for i in 2..100 {
        sig[i] = 0xFF;
    }
    sig[100] = 0x00;

    let start = Instant::now();
    for _ in 0..10000 {
        let _ = redmi_tls::core::crypto::SignatureVerifier::verify_rsa_signature(
            b"message",
            &sig,
            &[],
            redmi_tls::core::crypto::HashAlgorithm::SHA256,
        );
    }
    let duration = start.elapsed();
    println!("   10000 iterations: {:?} ({:.3} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 10000.0
    );

    println!("\n6. ECDSA Signature Validation (format check):");
    let ecdsa_sig = vec![0x42u8; 64];

    let start = Instant::now();
    for _ in 0..10000 {
        let _ = redmi_tls::core::crypto::SignatureVerifier::verify_ecdsa_signature(
            b"message",
            &ecdsa_sig,
            &[],
            redmi_tls::core::crypto::HashAlgorithm::SHA256,
            redmi_tls::core::crypto::ECDSACurve::P256,
        );
    }
    let duration = start.elapsed();
    println!("   10000 iterations: {:?} ({:.3} µs/op)", 
        duration, 
        duration.as_micros() as f64 / 10000.0
    );

    println!("\n{}", "─".repeat(60));
    println!("\n✅ All crypto operations benchmarked successfully!");
}
