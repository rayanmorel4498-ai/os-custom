extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;
use alloc::sync::Arc;

#[derive(Clone, Debug)]
pub struct RecordBatch {
    pub records: Vec<Vec<u8>>,
    pub total_size: usize,
    pub created_at: u64,
    pub max_batch_size: usize,
}

impl RecordBatch {
    pub fn is_full(&self) -> bool {
        self.total_size >= self.max_batch_size
    }

    pub fn add_record(&mut self, record: Vec<u8>) -> bool {
        let record_size = record.len();
        if self.total_size + record_size > self.max_batch_size && !self.records.is_empty() {
            return false;
        }
        
        self.total_size += record_size;
        self.records.push(record);
        true
    }

    pub fn get_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for record in &self.records {
            data.extend_from_slice(record);
        }
        data
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.total_size = 0;
    }
}

pub struct RecordBatcher {
    current_batch: Arc<Mutex<RecordBatch>>,
    #[allow(dead_code)]
    max_batch_size: usize,
    batch_timeout_ms: u64,
    batches_flushed: Arc<AtomicU64>,
    records_batched: Arc<AtomicU64>,
    bytes_batched: Arc<AtomicU64>,
}

impl RecordBatcher {
    pub fn new(max_batch_size: usize, batch_timeout_ms: u64) -> Self {
        Self {
            current_batch: Arc::new(Mutex::new(RecordBatch {
                records: Vec::new(),
                total_size: 0,
                created_at: Self::current_time_ms(),
                max_batch_size,
            })),
            max_batch_size,
            batch_timeout_ms,
            batches_flushed: Arc::new(AtomicU64::new(0)),
            records_batched: Arc::new(AtomicU64::new(0)),
            bytes_batched: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_record(&self, record: Vec<u8>) -> bool {
        let bytes = record.len() as u64;
        let mut batch = self.current_batch.lock();
        
        let added = batch.add_record(record);
        if added {
            self.records_batched.fetch_add(1, Ordering::SeqCst);
            self.bytes_batched.fetch_add(bytes, Ordering::SeqCst);
        }
        
        added
    }

    pub fn try_flush(&self) -> Option<Vec<u8>> {
        let mut batch = self.current_batch.lock();
        
        if batch.records.is_empty() {
            return None;
        }

        let now = Self::current_time_ms();
        let batch_age = now.saturating_sub(batch.created_at);
        
        if batch.is_full() || batch_age >= self.batch_timeout_ms {
            let data = batch.get_data();
            batch.clear();
            batch.created_at = now;
            self.batches_flushed.fetch_add(1, Ordering::SeqCst);
            return Some(data);
        }
        
        None
    }

    pub fn force_flush(&self) -> Option<Vec<u8>> {
        let mut batch = self.current_batch.lock();
        
        if batch.records.is_empty() {
            return None;
        }

        let data = batch.get_data();
        batch.clear();
        batch.created_at = Self::current_time_ms();
        self.batches_flushed.fetch_add(1, Ordering::SeqCst);
        Some(data)
    }

    pub fn get_batch_size(&self) -> usize {
        self.current_batch.lock().total_size
    }

    pub fn get_record_count(&self) -> usize {
        self.current_batch.lock().records.len()
    }

    pub fn stats(&self) -> RecordBatchingStats {
        let batch = self.current_batch.lock();
        
        RecordBatchingStats {
            current_batch_records: batch.records.len(),
            current_batch_size: batch.total_size,
            batches_flushed: self.batches_flushed.load(Ordering::SeqCst),
            total_records_batched: self.records_batched.load(Ordering::SeqCst),
            total_bytes_batched: self.bytes_batched.load(Ordering::SeqCst),
        }
    }

    pub fn reset_stats(&self) {
        self.batches_flushed.store(0, Ordering::SeqCst);
        self.records_batched.store(0, Ordering::SeqCst);
        self.bytes_batched.store(0, Ordering::SeqCst);
    }

    fn current_time_ms() -> u64 {
        #[cfg(feature = "real_tls")]
        {
            
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        }
        #[cfg(not(feature = "real_tls"))]
        {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecordBatchingStats {
    pub current_batch_records: usize,
    pub current_batch_size: usize,
    pub batches_flushed: u64,
    pub total_records_batched: u64,
    pub total_bytes_batched: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_record() {
        let batcher = RecordBatcher::new(4096, 100);
        let record = b"test_record".to_vec();
        
        assert!(batcher.add_record(record));
    }

    #[test]
    fn test_try_flush() {
        let batcher = RecordBatcher::new(100, 5000);
        let record = b"test_record_data".to_vec();
        
        batcher.add_record(record);
        assert!(batcher.try_flush().is_none());
    }

    #[test]
    fn test_force_flush() {
        let batcher = RecordBatcher::new(4096, 5000);
        let record = b"test_record_data".to_vec();
        
        batcher.add_record(record.clone());
        let flushed = batcher.force_flush();
        
        assert!(flushed.is_some());
        assert_eq!(flushed.unwrap(), record);
    }

    #[test]
    fn test_get_batch_size() {
        let batcher = RecordBatcher::new(4096, 5000);
        let record = b"test_record".to_vec();
        let size = record.len();
        
        batcher.add_record(record);
        assert_eq!(batcher.get_batch_size(), size);
    }

    #[test]
    fn test_get_record_count() {
        let batcher = RecordBatcher::new(4096, 5000);
        
        batcher.add_record(b"record1".to_vec());
        batcher.add_record(b"record2".to_vec());
        
        assert_eq!(batcher.get_record_count(), 2);
    }

    #[test]
    fn test_stats() {
        let batcher = RecordBatcher::new(4096, 5000);
        
        batcher.add_record(b"record1".to_vec());
        batcher.add_record(b"record2".to_vec());
        
        let stats = batcher.stats();
        assert_eq!(stats.current_batch_records, 2);
        assert_eq!(stats.total_records_batched, 2);
    }

    #[test]
    fn test_reset_stats() {
        let batcher = RecordBatcher::new(4096, 5000);
        
        batcher.add_record(b"record".to_vec());
        batcher.reset_stats();
        
        let stats = batcher.stats();
        assert_eq!(stats.total_records_batched, 0);
    }
}
