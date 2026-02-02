use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::Vec;

pub struct StreamBuffer {
    buffer: Arc<Mutex<Vec<u8>>>,
    capacity: usize,
}

impl StreamBuffer {
    pub fn new(capacity: usize) -> Self {
        StreamBuffer {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            capacity,
        }
    }

    pub fn push_chunk(&self, chunk: &[u8]) -> bool {
        let mut buf = self.buffer.lock();
        if buf.len() + chunk.len() <= self.capacity {
            buf.extend_from_slice(chunk);
            true
        } else {
            false
        }
    }

    pub fn pop_chunk(&self, size: usize) -> Vec<u8> {
        let mut buf = self.buffer.lock();
        let drain_size = if size > buf.len() { buf.len() } else { size };
        buf.drain(0..drain_size).collect()
    }

    pub fn len(&self) -> usize {
        self.buffer.lock().len()
    }

    pub fn is_full(&self) -> bool {
        self.buffer.lock().len() >= self.capacity
    }
}
