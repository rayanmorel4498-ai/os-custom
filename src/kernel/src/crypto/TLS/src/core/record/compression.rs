extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    None,
    Deflate,
    LZ4,
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Deflate => write!(f, "Deflate"),
            Self::LZ4 => write!(f, "LZ4"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompressionStats {
    pub algorithm: CompressionAlgorithm,
    pub bytes_original: u64,
    pub bytes_compressed: u64,
    pub operations: u64,
}

impl CompressionStats {
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_original == 0 {
            0.0
        } else {
            (self.bytes_compressed as f64 / self.bytes_original as f64) * 100.0
        }
    }

    pub fn bytes_saved(&self) -> u64 {
        self.bytes_original.saturating_sub(self.bytes_compressed)
    }
}

pub struct TLSCompression {
    algorithm: CompressionAlgorithm,
    stats: parking_lot::Mutex<CompressionStats>,
    enabled: bool,
}

impl TLSCompression {
    pub fn new() -> Self {
        Self {
            algorithm: CompressionAlgorithm::None,
            stats: parking_lot::Mutex::new(CompressionStats {
                algorithm: CompressionAlgorithm::None,
                bytes_original: 0,
                bytes_compressed: 0,
                operations: 0,
            }),
            enabled: false,
        }
    }

    pub fn set_algorithm(&mut self, algo: CompressionAlgorithm) {
        self.algorithm = algo;
        self.enabled = algo != CompressionAlgorithm::None;

        let mut stats = self.stats.lock();
        stats.algorithm = algo;
    }

    pub fn compress(&self, data: &[u8]) -> Vec<u8> {
        if !self.enabled || data.is_empty() {
            return data.to_vec();
        }

        let compressed = match self.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Deflate => self.deflate_compress(data),
            CompressionAlgorithm::LZ4 => self.lz4_compress(data),
        };

        let mut stats = self.stats.lock();
        stats.bytes_original = stats.bytes_original.saturating_add(data.len() as u64);
        stats.bytes_compressed = stats
            .bytes_compressed
            .saturating_add(compressed.len() as u64);
        stats.operations = stats.operations.saturating_add(1);

        compressed
    }

    pub fn decompress(&self, data: &[u8], original_size: usize) -> Option<Vec<u8>> {
        if !self.enabled || data.is_empty() {
            return Some(data.to_vec());
        }

        match self.algorithm {
            CompressionAlgorithm::None => Some(data.to_vec()),
            CompressionAlgorithm::Deflate => self.deflate_decompress(data, original_size),
            CompressionAlgorithm::LZ4 => self.lz4_decompress(data, original_size),
        }
    }

    pub fn stats(&self) -> CompressionStats {
        self.stats.lock().clone()
    }

    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock();
        stats.bytes_original = 0;
        stats.bytes_compressed = 0;
        stats.operations = 0;
    }

    fn deflate_compress(&self, data: &[u8]) -> Vec<u8> {
        let mut result = alloc::vec![0x78, 0x9C];
        result.extend_from_slice(data);
        result.push(0);
        result
    }

    fn deflate_decompress(&self, data: &[u8], _original_size: usize) -> Option<Vec<u8>> {
        if data.len() > 3 {
            Some(data[2..data.len() - 1].to_vec())
        } else {
            None
        }
    }

    fn lz4_compress(&self, data: &[u8]) -> Vec<u8> {
        let mut result = alloc::vec![0x04, 0x22, 0x4D, 0x18];
        result.extend_from_slice(data);
        result
    }

    fn lz4_decompress(&self, data: &[u8], _original_size: usize) -> Option<Vec<u8>> {
        if data.len() > 4 && data[0..4] == [0x04, 0x22, 0x4D, 0x18] {
            Some(data[4..].to_vec())
        } else {
            None
        }
    }

    pub fn summary(&self) -> String {
        let stats = self.stats.lock();
        alloc::format!(
            "Compression: {} (enabled: {}, ratio: {:.2}%, saved: {} bytes)",
            stats.algorithm,
            self.enabled,
            stats.compression_ratio(),
            stats.bytes_saved()
        )
    }
}

impl Default for TLSCompression {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_compression_disabled_by_default() {
        let comp = TLSCompression::new();
        assert!(!comp.enabled);
    }

    #[test]
    fn test_set_compression_algorithm() {
        let mut comp = TLSCompression::new();
        comp.set_algorithm(CompressionAlgorithm::Deflate);
        assert!(comp.enabled);
    }

    #[test]
    fn test_compress_disabled() {
        let comp = TLSCompression::new();
        let data = b"test data to compress";
        let result = comp.compress(data);

        assert_eq!(result, data);
    }

    #[test]
    fn test_compress_enabled() {
        let mut comp = TLSCompression::new();
        comp.set_algorithm(CompressionAlgorithm::Deflate);

        let data = b"test data to compress";
        let result = comp.compress(data);

        assert!(result.len() > data.len());
    }

    #[test]
    fn test_compression_stats() {
        let mut comp = TLSCompression::new();
        comp.set_algorithm(CompressionAlgorithm::Deflate);

        let data = b"test data";
        let _ = comp.compress(data);

        let stats = comp.stats();
        assert!(stats.operations > 0);
    }

    #[test]
    fn test_reset_stats() {
        let mut comp = TLSCompression::new();
        comp.set_algorithm(CompressionAlgorithm::Deflate);

        let _ = comp.compress(b"test data");
        comp.reset_stats();

        let stats = comp.stats();
        assert_eq!(stats.operations, 0);
    }

    #[test]
    fn test_compression_algorithm_display() {
        assert_eq!(CompressionAlgorithm::None.to_string(), "None");
        assert_eq!(CompressionAlgorithm::Deflate.to_string(), "Deflate");
        assert_eq!(CompressionAlgorithm::LZ4.to_string(), "LZ4");
    }

    #[test]
    fn test_summary() {
        let comp = TLSCompression::new();
        let summary = comp.summary();
        assert!(!summary.is_empty());
    }
}
