
use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;

pub struct BufferPool {
    small: Vec<Vec<u8>>,
    medium: Vec<Vec<u8>>,
    large: Vec<Vec<u8>>,
}

impl BufferPool {
    pub fn new(small_count: usize, medium_count: usize, large_count: usize) -> Self {
        let mut small = Vec::with_capacity(small_count);
        for _ in 0..small_count {
            small.push(Vec::with_capacity(256));
        }
        let mut medium = Vec::with_capacity(medium_count);
        for _ in 0..medium_count {
            medium.push(Vec::with_capacity(4096));
        }
        let mut large = Vec::with_capacity(large_count);
        for _ in 0..large_count {
            large.push(Vec::with_capacity(16384));
        }
        Self { small, medium, large }
    }

    #[inline]
    pub fn get_small(&mut self) -> Option<Vec<u8>> {
        self.small.pop()
    }

    #[inline]
    pub fn get_medium(&mut self) -> Option<Vec<u8>> {
        self.medium.pop()
    }

    #[inline]
    pub fn get_large(&mut self) -> Option<Vec<u8>> {
        self.large.pop()
    }

    #[inline]
    pub fn return_small(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if self.small.len() < 16 {
            self.small.push(buf);
        }
    }

    #[inline]
    pub fn return_medium(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if self.medium.len() < 8 {
            self.medium.push(buf);
        }
    }

    #[inline]
    pub fn return_large(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if self.large.len() < 4 {
            self.large.push(buf);
        }
    }
}

#[inline]
pub fn use_stack_buffer<F, R>(size: usize, f: F) -> R
where
    F: FnOnce(&mut [u8]) -> R,
{
    if size <= 256 {
        let mut buf = [0u8; 256];
        f(&mut buf[..size])
    } else if size <= 1024 {
        let mut buf = [0u8; 1024];
        f(&mut buf[..size])
    } else {
        let mut buf = alloc::vec![0u8; size];
        f(&mut buf)
    }
}

#[inline(never)]
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut result: u32 = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= (x ^ y) as u32;
    }
    result == 0
}

pub struct BatchTimestampCache {
    last_timestamp: u64,
    batch_count: u32,
}

impl BatchTimestampCache {
    pub fn new() -> Self {
        Self {
            last_timestamp: 0,
            batch_count: 0,
        }
    }

    #[inline]
    pub fn get(&mut self) -> u64 {
        self.batch_count = self.batch_count.saturating_add(1);
        if self.batch_count >= 32 {
            self.last_timestamp = self.last_timestamp.saturating_add(1);
            self.batch_count = 0;
        }
        self.last_timestamp
    }
}

pub struct StreamBuffer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamBuffer<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn read(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Some(slice)
        } else {
            None
        }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

pub struct LazyHasher {
    data: Vec<u8>,
    cached_hash: Option<alloc::string::String>,
}

impl LazyHasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(256),
            cached_hash: None,
        }
    }

    #[inline]
    pub fn update(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
        self.cached_hash = None;
    }

    pub fn finalize_hex(&mut self) -> alloc::string::String {
        if let Some(ref h) = self.cached_hash {
            return h.clone();
        }
        let result = hex_encode(&self.data);
        self.cached_hash = Some(result.clone());
        result
    }
}

fn hex_encode(data: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &byte in data {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

pub trait TlsEventHandler {
    fn handle_connection(&mut self, data: &[u8]) -> bool;
    fn on_error(&mut self);
}

pub struct StringIntern {
    cache: Vec<String>,
}

impl StringIntern {
    pub fn new() -> Self {
        Self {
            cache: Vec::new(),
        }
    }

    pub fn intern(&mut self, s: &str) -> bool {
        if !self.cache.iter().any(|c| c == s) {
            self.cache.push(String::from(s));
            true
        } else {
            false
        }
    }

    pub fn contains(&self, s: &str) -> bool {
        self.cache.iter().any(|c| c == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let mut pool = BufferPool::new(2, 2, 2);
        assert!(pool.get_small().is_some());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
    }
}
