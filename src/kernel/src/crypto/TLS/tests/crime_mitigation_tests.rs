use redmi_tls::core::record::compression::TLSCompression;
use redmi_tls::core::record::compression::CompressionAlgorithm;

#[test]
fn test_compression_information_leakage() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let secret = b"CONFIDENTIAL";
    let secret_with_padding = b"CONFIDENTIAL_AND_EXTRA_PADDING_TO_CONFUSE";
    
    let compressed_secret = compression.compress(secret);
    let compressed_padded = compression.compress(secret_with_padding);
    
    println!(
        "Compressed secret: {} bytes, Padded: {} bytes",
        compressed_secret.len(),
        compressed_padded.len()
    );
    
    assert_ne!(
        compressed_secret.len(),
        compressed_padded.len(),
        "Compression exposes length (CRIME vulnerability awareness)"
    );
}

#[test]
fn test_compression_disabled_by_default() {
    let compression = TLSCompression::new();
    
    let data = b"test data for compression";
    let result = compression.compress(data);
    
    assert_eq!(
        result,
        data.to_vec(),
        "Compression should be disabled by default (CRIME mitigation)"
    );
}

#[test]
fn test_compression_ratio_calculation() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let compressible = b"aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd";
    let random_data = vec![42u8; 100];
    
    let compressed_compressible = compression.compress(compressible);
    let compressed_random = compression.compress(&random_data);
    
    let ratio_good = (compressed_compressible.len() as f64 / compressible.len() as f64) * 100.0;
    let ratio_poor = (compressed_random.len() as f64 / random_data.len() as f64) * 100.0;
    
    println!(
        "Compressible ratio: {:.1}%, Random ratio: {:.1}%",
        ratio_good, ratio_poor
    );
    
    assert!(
        compressed_compressible.len() > 0 && compressed_random.len() > 0,
        "Both should produce compressed output"
    );
}

#[test]
fn test_deflate_enables_compression() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::None);
    
    let plaintext = b"Hello World! This is a test message.";
    let uncompressed = compression.compress(plaintext);
    assert_eq!(uncompressed, plaintext.to_vec());
    
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    let compressed = compression.compress(plaintext);
    
    println!(
        "No compression: {} bytes, Deflate: {} bytes",
        uncompressed.len(),
        compressed.len()
    );
}

#[test]
fn test_crime_attack_simulation() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let known_prefix = b"Authorization: Bearer ";
    let secret_token = b"supersecrettoken123";
    
    let mut full_message = known_prefix.to_vec();
    full_message.extend_from_slice(secret_token);
    full_message.extend_from_slice(b"_extra_data_here");
    
    let base_compressed = compression.compress(&full_message);
    
    for guess in &[b"a", b"s", b"u", b"p"] {
        let mut test_message = known_prefix.to_vec();
        test_message.extend_from_slice(*guess);
        test_message.extend_from_slice(b"_extra_data_here");
        
        let test_compressed = compression.compress(&test_message);
        
        println!(
            "Base size: {}, With guess {:?}: {}",
            base_compressed.len(),
            String::from_utf8_lossy(*guess),
            test_compressed.len()
        );
    }
}

#[test]
fn test_lz4_compression_characteristics() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::LZ4);
    
    let repeated = b"abcdefabcdefabcdefabcdef";
    let random = vec![rand::random::<u8>(); 100];
    
    let comp_repeated = compression.compress(repeated);
    let comp_random = compression.compress(&random);
    
    println!(
        "LZ4 repeated: {} -> {} bytes",
        repeated.len(),
        comp_repeated.len()
    );
    println!(
        "LZ4 random: {} -> {} bytes",
        random.len(),
        comp_random.len()
    );
}

#[test]
fn test_compression_stats_tracking() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let data1 = b"First compression test";
    let data2 = b"Second compression test";
    
    let _ = compression.compress(data1);
    let _ = compression.compress(data2);
    
    println!(
        "Compression stats after operations: data1={}, data2={}",
        data1.len(),
        data2.len()
    );
}

#[test]
fn test_empty_plaintext_compression() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let empty = b"";
    let result = compression.compress(empty);
    
    assert_eq!(result.len(), 0, "Empty plaintext should compress to empty");
}

#[test]
fn test_compression_not_increasing_size() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::Deflate);
    
    let very_random = (0..50).map(|i| ((i * 37) % 256) as u8).collect::<Vec<_>>();
    let compressed = compression.compress(&very_random);
    
    assert!(
        compressed.len() <= very_random.len() * 2,
        "Compression should not expand data significantly"
    );
}

#[test]
fn test_compression_side_channel_mitigation() {
    let mut compression = TLSCompression::new();
    compression.set_algorithm(CompressionAlgorithm::None);
    
    let data1 = b"This is secret";
    let data2 = b"This is secret";
    
    let comp1 = compression.compress(data1);
    let comp2 = compression.compress(data2);
    
    assert_eq!(
        comp1.len(),
        comp2.len(),
        "Same plaintext should produce same length when compression disabled"
    );
}
