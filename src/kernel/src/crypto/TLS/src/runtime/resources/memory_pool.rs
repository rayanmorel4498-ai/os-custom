extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct PoolConfig {
    pub block_size: usize,
    pub block_count: usize,
}

#[derive(Clone, Debug)]
pub struct MemoryBlock {
    pub data: Vec<u8>,
    pub is_allocated: bool,
    pub allocated_at: u64,
}

pub struct MemoryPool {
    #[allow(dead_code)]
    config: PoolConfig,
    block_size: usize,
    block_count: usize,
    blocks: Arc<RwLock<BTreeMap<usize, MemoryBlock>>>,
    #[allow(dead_code)]
    next_block_id: Arc<AtomicU64>,
    allocations: Arc<AtomicU64>,
    deallocations: Arc<AtomicU64>,
    active_blocks: Arc<AtomicU64>,
    max_active: Arc<AtomicU64>,
}

impl MemoryPool {
    pub fn new(config: PoolConfig) -> Self {
        let block_size = config.block_size;
        let block_count = config.block_count;
        let mut blocks = BTreeMap::new();
        
        for i in 0..config.block_count {
            blocks.insert(
                i,
                MemoryBlock {
                    data: alloc::vec![0u8; config.block_size],
                    is_allocated: false,
                    allocated_at: 0,
                },
            );
        }

        Self {
            config,
            block_size,
            block_count,
            blocks: Arc::new(RwLock::new(blocks)),
            next_block_id: Arc::new(AtomicU64::new(config.block_count as u64)),
            allocations: Arc::new(AtomicU64::new(0)),
            deallocations: Arc::new(AtomicU64::new(0)),
            active_blocks: Arc::new(AtomicU64::new(0)),
            max_active: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn allocate(&self) -> Option<usize> {
        let mut blocks = self.blocks.write();
        
        for (id, block) in blocks.iter_mut() {
            if !block.is_allocated {
                block.is_allocated = true;
                block.allocated_at = Self::current_time();
                
                self.allocations.fetch_add(1, Ordering::SeqCst);
                let active = self.active_blocks.fetch_add(1, Ordering::SeqCst) + 1;
                
                let mut max = self.max_active.load(Ordering::SeqCst);
                while active as u64 > max {
                    match self.max_active.compare_exchange(
                        max,
                        active as u64,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(actual) => max = actual,
                    }
                }
                
                return Some(*id);
            }
        }
        
        None
    }

    pub fn deallocate(&self, block_id: usize) -> bool {
        let mut blocks = self.blocks.write();
        
        if let Some(block) = blocks.get_mut(&block_id) {
            if block.is_allocated {
                block.is_allocated = false;
                block.allocated_at = 0;
                self.deallocations.fetch_add(1, Ordering::SeqCst);
                self.active_blocks.fetch_sub(1, Ordering::SeqCst);
                return true;
            }
        }
        
        false
    }

    pub fn get_block(&self, block_id: usize) -> Option<Vec<u8>> {
        let blocks = self.blocks.read();
        blocks.get(&block_id).map(|block| block.data.clone())
    }

    pub fn get_block_size(&self, block_id: usize) -> Option<usize> {
        let blocks = self.blocks.read();
        blocks.get(&block_id).map(|_| self.block_size)
    }

    pub fn write_block(&self, block_id: usize, data: &[u8]) -> bool {
        if data.len() > self.block_size {
            return false;
        }

        let mut blocks = self.blocks.write();
        if let Some(block) = blocks.get_mut(&block_id) {
            if block.is_allocated {
                block.data[..data.len()].copy_from_slice(data);
                return true;
            }
        }
        
        false
    }

    pub fn is_allocated(&self, block_id: usize) -> bool {
        let blocks = self.blocks.read();
        blocks
            .get(&block_id)
            .map(|block| block.is_allocated)
            .unwrap_or(false)
    }

    pub fn stats(&self) -> MemoryPoolStats {
        let blocks = self.blocks.read();
        let total_blocks = blocks.len();
        let allocated = blocks.values().filter(|b| b.is_allocated).count();
        let free = total_blocks - allocated;

        MemoryPoolStats {
            total_blocks,
            allocated_blocks: allocated,
            free_blocks: free,
            block_size: self.block_size,
            total_memory: total_blocks * self.block_size,
            allocated_memory: allocated * self.block_size,
            free_memory: free * self.block_size,
            total_allocations: self.allocations.load(Ordering::SeqCst),
            total_deallocations: self.deallocations.load(Ordering::SeqCst),
            max_concurrent_allocations: self.max_active.load(Ordering::SeqCst),
        }
    }

    pub fn compact(&self) {
        let mut blocks = self.blocks.write();
        
        let allocated_count = blocks.values().filter(|b| b.is_allocated).count();
        
        if allocated_count == 0 {
            blocks.clear();
            
            for i in 0..self.block_count {
                blocks.insert(
                    i,
                    MemoryBlock {
                        data: alloc::vec![0u8; self.block_size],
                        is_allocated: false,
                        allocated_at: 0,
                    },
                );
            }
        }
    }

    pub fn clear(&self) {
        self.blocks.write().clear();
    }

    fn current_time() -> u64 {
        #[cfg(feature = "real_tls")]
        {
            
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
        #[cfg(not(feature = "real_tls"))]
        {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoryPoolStats {
    pub total_blocks: usize,
    pub allocated_blocks: usize,
    pub free_blocks: usize,
    pub block_size: usize,
    pub total_memory: usize,
    pub allocated_memory: usize,
    pub free_memory: usize,
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub max_concurrent_allocations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        let stats = pool.stats();
        
        assert_eq!(stats.total_blocks, 10);
        assert_eq!(stats.free_blocks, 10);
    }

    #[test]
    fn test_allocate() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        let block_id = pool.allocate();
        assert!(block_id.is_some());
    }

    #[test]
    fn test_deallocate() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        let block_id = pool.allocate().unwrap();
        assert!(pool.deallocate(block_id));
    }

    #[test]
    fn test_get_block() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        let block_id = pool.allocate().unwrap();
        let block = pool.get_block(block_id);
        
        assert!(block.is_some());
        assert_eq!(block.unwrap().len(), 1024);
    }

    #[test]
    fn test_write_block() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        let block_id = pool.allocate().unwrap();
        let data = b"test_data";
        
        assert!(pool.write_block(block_id, data));
    }

    #[test]
    fn test_is_allocated() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        let block_id = pool.allocate().unwrap();
        assert!(pool.is_allocated(block_id));
    }

    #[test]
    fn test_stats() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        pool.allocate();
        let stats = pool.stats();
        
        assert_eq!(stats.allocated_blocks, 1);
        assert_eq!(stats.free_blocks, 9);
    }

    #[test]
    fn test_clear() {
        let config = PoolConfig {
            block_size: 1024,
            block_count: 10,
        };
        let pool = MemoryPool::new(config);
        
        pool.allocate();
        pool.clear();
        
        assert_eq!(pool.stats().total_blocks, 0);
    }
}
