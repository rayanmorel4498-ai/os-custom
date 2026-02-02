use alloc::vec::Vec;

pub struct SIMDBuffer {
    data: Vec<u8>,
    simd_aligned: bool,
}

impl SIMDBuffer {
    pub fn new(capacity: usize) -> Self {
        let data = Vec::with_capacity(capacity);
        let aligned = (data.as_ptr() as usize) % 64 == 0;
        Self {
            data,
            simd_aligned: aligned,
        }
    }

    #[inline]
    pub fn push_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    pub fn is_simd_aligned(&self) -> bool {
        self.simd_aligned
    }

    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

pub struct CacheLineBuffer {
    line: [u8; 64],
    pos: usize,
}

impl CacheLineBuffer {
    pub fn new() -> Self {
        Self {
            line: [0u8; 64],
            pos: 0,
        }
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = 64 - self.pos;
        let to_write = core::cmp::min(available, data.len());
        self.line[self.pos..self.pos + to_write].copy_from_slice(&data[..to_write]);
        self.pos += to_write;
        to_write
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.pos >= 64
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.line[..self.pos]
    }

    #[inline]
    pub fn reset(&mut self) {
        self.pos = 0;
    }
}

pub struct VectorizedLoop {
    iteration: u32,
    max_iterations: u32,
}

impl VectorizedLoop {
    pub fn new(max_iterations: u32) -> Self {
        Self {
            iteration: 0,
            max_iterations,
        }
    }

    #[inline]
    pub fn next_unroll_4<F>(&mut self, mut f: F) -> bool
    where
        F: FnMut(u32),
    {
        if self.iteration >= self.max_iterations {
            return false;
        }
        
        let mut i = self.iteration;
        while i + 4 <= self.max_iterations && self.iteration + 4 <= self.max_iterations {
            f(i); f(i + 1); f(i + 2); f(i + 3);
            i += 4;
            self.iteration += 4;
        }
        
        while self.iteration < self.max_iterations {
            f(self.iteration);
            self.iteration += 1;
        }
        
        true
    }

    #[inline]
    pub fn current(&self) -> u32 {
        self.iteration
    }

    #[inline]
    pub fn reset(&mut self) {
        self.iteration = 0;
    }
}

pub struct PackedInt32Array {
    data: Vec<u32>,
}

impl PackedInt32Array {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    #[inline]
    pub fn push(&mut self, value: u32) {
        self.data.push(value);
    }

    #[inline]
    pub fn simd_add(&self, other: &[u32]) -> Vec<u32> {
        self.data
            .iter()
            .zip(other.iter())
            .map(|(a, b)| a.wrapping_add(*b))
            .collect()
    }

    #[inline]
    pub fn simd_xor(&self, other: &[u32]) -> Vec<u32> {
        self.data
            .iter()
            .zip(other.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

pub struct AES256Precompute {
    round_keys: Vec<[u32; 4]>,
}

impl AES256Precompute {
    pub fn new(key: &[u8]) -> Option<Self> {
        if key.len() != 32 {
            return None;
        }

        let mut round_keys: Vec<[u32; 4]> = Vec::with_capacity(60);
        
        for i in 0..32 {
            let idx = i / 4;
            let offset = i % 4;
            if idx >= round_keys.len() {
                round_keys.push([0u32; 4]);
            }
            round_keys[idx][offset] = u32::from_le_bytes([
                key[i], key[i+1], key[i+2], key[i+3],
            ]);
        }

        Some(Self { round_keys })
    }

    #[inline]
    pub fn round_key(&self, round: usize) -> Option<&[u32; 4]> {
        self.round_keys.get(round)
    }

    #[inline]
    pub fn rounds(&self) -> usize {
        self.round_keys.len()
    }
}

pub struct PrefetchHint {
    addr: *const u8,
    level: u8,
}

impl PrefetchHint {
    pub fn new(addr: *const u8, level: u8) -> Self {
        Self { addr, level }
    }

    #[inline]
    pub fn execute(&self) {
        unsafe {
            #[cfg(target_arch = "x86_64")]
            {
                match self.level {
                    0 => core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(self.addr as *const i8),
                    1 => core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T1 }>(self.addr as *const i8),
                    2 => core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T2 }>(self.addr as *const i8),
                    _ => {}
                }
            }
        }
    }
}

pub struct LoopUnroll;

impl LoopUnroll {
    #[inline]
    pub fn unroll_8<F>(n: usize, mut f: F)
    where
        F: FnMut(usize),
    {
        let chunks = n / 8;
        let remainder = n % 8;
        
        for chunk in 0..chunks {
            let base = chunk * 8;
            f(base);
            f(base + 1);
            f(base + 2);
            f(base + 3);
            f(base + 4);
            f(base + 5);
            f(base + 6);
            f(base + 7);
        }
        
        for i in 0..remainder {
            f(chunks * 8 + i);
        }
    }

    #[inline]
    pub fn unroll_16<F>(n: usize, mut f: F)
    where
        F: FnMut(usize),
    {
        let chunks = n / 16;
        let remainder = n % 16;
        
        for chunk in 0..chunks {
            let base = chunk * 16;
            for i in 0..16 {
                f(base + i);
            }
        }
        
        for i in 0..remainder {
            f(chunks * 16 + i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_buffer() {
        let mut buf = SIMDBuffer::new(128);
        buf.push_slice(b"hello");
        assert_eq!(buf.as_slice(), b"hello");
    }

    #[test]
    fn test_cache_line_buffer() {
        let mut buf = CacheLineBuffer::new();
        let written = buf.write(b"test");
        assert_eq!(written, 4);
        assert_eq!(buf.as_slice(), b"test");
    }

    #[test]
    fn test_vectorized_loop() {
        let mut vloop = VectorizedLoop::new(10);
        let mut count = 0;
        vloop.next_unroll_4(|_| {
            count += 1;
        });
        assert_eq!(count, 10);
    }

    #[test]
    fn test_packed_int32() {
        let mut arr = PackedInt32Array::new(4);
        arr.push(1);
        arr.push(2);
        arr.push(3);
        arr.push(4);
        assert_eq!(arr.len(), 4);
    }
}
