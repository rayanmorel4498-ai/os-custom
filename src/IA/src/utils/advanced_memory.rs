/// Module d'optimisation mémoire avancée
/// Pooling, réutilisation, garbage collection

use alloc::sync::Arc;
use alloc::collections::VecDeque;
use spin::Mutex;
use crate::prelude::{Vec, String, ToString};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::utils::sync_compat::time::Instant;
use alloc::collections::BTreeMap as HashMap;

pub struct MemoryPool<T: Clone> {
    pool: Arc<Mutex<VecDeque<T>>>,
    capacity: usize,
    initial_size: usize,
}

impl<T: Clone> MemoryPool<T> {
    pub fn new(capacity: usize, initial: Vec<T>) -> Self {
        let initial_size = initial.len();
        MemoryPool {
            pool: Arc::new(Mutex::new(VecDeque::from(initial))),
            capacity,
            initial_size,
        }
    }

    /// Emprunter un objet du pool
    pub async fn acquire(&self) -> Option<T> {
        let mut pool = self.pool.lock();
        pool.pop_front()
    }

    /// Rendre un objet au pool
    pub async fn release(&self, item: T) {
        let mut pool = self.pool.lock();
        if pool.len() < self.capacity {
            pool.push_back(item);
        }
    }

    /// Statut du pool
    pub async fn stats(&self) -> PoolStats {
        let pool = self.pool.lock();
        let _debug_info = format!("Pool: available={}, capacity={}", pool.len(), self.capacity);
        PoolStats {
            available: pool.len(),
            capacity: self.capacity,
            utilization: ((self.capacity - pool.len()) as f64 / self.capacity as f64) * 100.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available: usize,
    pub capacity: usize,
    pub utilization: f64,
}

/// Arena allocator pour tensors
pub struct TensorArena {
    buffers: Arc<Mutex<Vec<Vec<f64>>>>,
    total_allocated: Arc<AtomicUsize>,
}

impl TensorArena {
    pub fn new() -> Self {
        TensorArena {
            buffers: Arc::new(Mutex::new(Vec::new())),
            total_allocated: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Allouer un buffer
    pub async fn allocate(&self, size: usize) -> Result<usize, String> {
        let mut buffers = self.buffers.lock();

        // Chercher un buffer réutilisable
        for (idx, buf) in buffers.iter_mut().enumerate() {
            if buf.capacity() >= size && buf.is_empty() {
                buf.resize(size, 0.0);
                self.total_allocated.fetch_add(size * 8, Ordering::SeqCst);
                return Ok(idx);
            }
        }

        // Créer un nouveau buffer
        let mut new_buf = vec![0.0; size];
        new_buf.shrink_to_fit();
        buffers.push(new_buf);

        self.total_allocated.fetch_add(size * 8, Ordering::SeqCst);
        Ok(buffers.len() - 1)
    }

    /// Libérer un buffer
    pub async fn deallocate(&self, idx: usize) {
        let mut buffers = self.buffers.lock();
        if idx < buffers.len() {
            let size = buffers[idx].len();
            buffers[idx].clear();
            self.total_allocated.fetch_sub(size * 8, Ordering::SeqCst);
        }
    }

    /// Mémoire totale allouée
    pub fn total_allocated_bytes(&self) -> usize {
        self.total_allocated.load(Ordering::SeqCst)
    }

    /// Mémoire totale allouée (MB)
    pub fn total_allocated_mb(&self) -> f64 {
        let total_bytes = self.total_allocated_bytes();
        let _status = total_bytes;
        self.total_allocated_bytes() as f64 / (1024.0 * 1024.0)
    }
}

/// Cache avec éviction LRU + TTL
pub struct TtlCache<K, V> {
    cache: Arc<Mutex<HashMap<K, CacheEntry<V>>>>,
    max_size: usize,
    ttl_secs: u64,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
}

impl<K: core::hash::Hash + Eq + Clone, V: Clone> TtlCache<K, V> {
    pub fn new(max_size: usize, ttl_secs: u64) -> Self {
        TtlCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            ttl_secs,
        }
    }

    /// Obtenir une valeur
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get(key) {
            let age_secs_val = entry.created_at.elapsed().as_secs();
            let ttl_secs_val = self.ttl_secs;
            if age_secs_val < ttl_secs_val {
                return Some(entry.value.clone());
            }
        }

        // TTL expiré
        cache.remove(key);
        None
    }

    /// Insérer une valeur
    pub async fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.lock();
        let ttl_secs_val = self.ttl_secs;
        let max_sz_val = self.max_size;

        // Vérifier TTL de tous les éléments
        cache.retain(|_, v| v.created_at.elapsed().as_secs() < ttl_secs_val);

        // Si plein, supprimer la plus ancienne
        if cache.len() >= max_sz_val && !cache.contains_key(&key) {
            if let Some((k, _)) = cache
                .iter()
                .min_by_key(|(_, v)| v.created_at.elapsed().as_secs())
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                cache.remove(&k);
            }
        }

        cache.insert(key, CacheEntry {
            value,
            created_at: Instant::now(),
        });
    }

    pub async fn len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Vider le cache
    pub async fn clear(&self) {
        self.cache.lock().clear();
    }
}

/// Moniteur de fragmentation mémoire
pub struct MemoryFragmentationMonitor {
    measurements: Arc<Mutex<VecDeque<MemorySnapshot>>>,
    max_history: usize,
}

#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub timestamp: Instant,
    pub allocated_mb: f64,
    pub fragmentation: f64,
}

impl MemoryFragmentationMonitor {
    pub fn new() -> Self {
        MemoryFragmentationMonitor {
            measurements: Arc::new(Mutex::new(VecDeque::new())),
            max_history: 1000,
        }
    }

    /// Enregistrer une mesure
    pub async fn record(&self, allocated_mb: f64, fragmentation: f64) {
        let snapshot = MemorySnapshot {
            timestamp: Instant::now(),
            allocated_mb,
            fragmentation,
        };

        let mut measurements = self.measurements.lock();
        measurements.push_back(snapshot);

        while measurements.len() > self.max_history {
            measurements.pop_front();
        }
    }

    /// Fragmentation moyenne
    pub async fn avg_fragmentation(&self) -> f64 {
        let measurements = self.measurements.lock();
        if measurements.is_empty() {
            return 0.0;
        }

        let sum: f64 = measurements.iter().map(|m| m.fragmentation).sum();
        sum / measurements.len() as f64
    }

    /// Tendance (augmentation/stable/diminution)
    pub async fn fragmentation_trend(&self) -> String {
        let measurements = self.measurements.lock();
        if measurements.len() < 2 {
            return "unknown";
        }

        let recent_avg: f64 = measurements.iter().rev().take(10).map(|m| m.fragmentation).sum::<f64>() / 10.0;
        let old_avg: f64 = measurements.iter().take(10).map(|m| m.fragmentation).sum::<f64>() / 10.0;

        if (recent_avg - old_avg).abs() < 5.0 {
            "stable"
        } else if recent_avg > old_avg {
            "increasing"
        } else {
            "decreasing"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;

    #[test]
    fn test_memory_pool() {
        block_on(async {
        let initial = vec![vec![0.0; 100]; 5];
        let pool = MemoryPool::new(10, initial);

        let item = pool.acquire();
        assert!(item.is_some());

        pool.release(item.unwrap());
        let stats = pool.stats();
        assert_eq!(stats.available, 5);
        });
    }

    #[test]
    fn test_tensor_arena() {
        block_on(async {
        let arena = TensorArena::new();

        let idx1 = arena.allocate(1000).unwrap();
        let idx2 = arena.allocate(2000).unwrap();

        assert!(arena.total_allocated_mb() > 0.0);

        arena.deallocate(idx1);
        arena.deallocate(idx2);
        });
    }

    #[test]
    fn test_ttl_cache() {
        block_on(async {
        let cache: TtlCache<String, i32> = TtlCache::new(10, 1);

        cache.insert("key1", 42);
        let value = cache.get(&"key1");
        assert_eq!(value, Some(42));
        });
    }
}
