use crate::prelude::Vec;

pub struct Compressor {
    buffer: Vec<u8>,
}

impl Compressor {
    pub fn new() -> Self {
        Compressor {
            buffer: Vec::new(),
        }
    }

    pub fn compress(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut count = 1u8;
            while i + (count as usize) < data.len() && data[i + (count as usize)] == byte && count < 255 {
                count += 1;
            }
            if count > 2 {
                result.push(255);
                result.push(byte);
                result.push(count);
                i += count as usize;
            } else {
                for _ in 0..count {
                    result.push(byte);
                }
                i += count as usize;
            }
        }
        result
    }

    pub fn decompress(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if data[i] == 255 && i + 2 < data.len() {
                let byte = data[i + 1];
                let count = data[i + 2] as usize;
                for _ in 0..count {
                    result.push(byte);
                }
                i += 3;
            } else {
                result.push(data[i]);
                i += 1;
            }
        }
        result
    }
}
