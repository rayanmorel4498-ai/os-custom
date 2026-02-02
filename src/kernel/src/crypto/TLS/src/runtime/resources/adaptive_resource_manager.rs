extern crate alloc;
use alloc::sync::Arc;
use parking_lot::RwLock;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Clone)]
pub struct AdaptiveResourceManager {
    current_size: Arc<AtomicUsize>,
    min_size: usize,
    max_size: usize,
    utilization_threshold: usize,
    adjustment_factor: f64,
    last_resize: Arc<RwLock<u64>>,
    resize_cooldown_ms: u64,
    resize_count: Arc<AtomicU64>,
    current_utilization: Arc<AtomicU64>,
}

impl AdaptiveResourceManager {
    pub fn new(initial_size: usize, min_size: usize, max_size: usize) -> Self {
        assert!(min_size <= initial_size && initial_size <= max_size);
        
        Self {
            current_size: Arc::new(AtomicUsize::new(initial_size)),
            min_size,
            max_size,
            utilization_threshold: 75,
            adjustment_factor: 1.5,
            last_resize: Arc::new(RwLock::new(0)),
            resize_cooldown_ms: 5000,
            resize_count: Arc::new(AtomicU64::new(0)),
            current_utilization: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_config(
        initial_size: usize,
        min_size: usize,
        max_size: usize,
        threshold: usize,
        adjustment_factor: f64,
    ) -> Self {
        assert!(threshold > 0 && threshold <= 100);
        assert!(adjustment_factor > 1.0);
        
        let mut mgr = Self::new(initial_size, min_size, max_size);
        mgr.utilization_threshold = threshold;
        mgr.adjustment_factor = adjustment_factor;
        mgr
    }

    pub fn check_and_adapt(&self, current_usage: usize, current_time: u64) -> Option<AdaptationAction> {
        let current = self.current_size.load(Ordering::SeqCst);
        let utilization = if current > 0 {
            ((current_usage * 100) / current) as u64
        } else {
            0
        };
        
        self.current_utilization.store(utilization, Ordering::SeqCst);
        
        if utilization as usize >= self.utilization_threshold {
            let last_resize = *self.last_resize.read();
            if current_time - last_resize >= self.resize_cooldown_ms {
                if current < self.max_size {
                    let new_size = ((current as f64) * self.adjustment_factor).min(self.max_size as f64) as usize;
                    let new_size = new_size.max(current);
                    
                    self.current_size.store(new_size, Ordering::SeqCst);
                    *self.last_resize.write() = current_time;
                    self.resize_count.fetch_add(1, Ordering::SeqCst);
                    
                    return Some(AdaptationAction::Grow {
                        old_size: current,
                        new_size,
                        utilization: utilization as usize,
                    });
                }
            }
        } else if utilization < 30 && current > self.min_size {
            let last_resize = *self.last_resize.read();
            if current_time - last_resize >= self.resize_cooldown_ms {
                let shrink_factor = 1.0 / self.adjustment_factor;
                let new_size = ((current as f64) * shrink_factor).max(self.min_size as f64) as usize;
                let new_size = new_size.min(current - 1);
                
                if new_size >= self.min_size {
                    self.current_size.store(new_size, Ordering::SeqCst);
                    *self.last_resize.write() = current_time;
                    self.resize_count.fetch_add(1, Ordering::SeqCst);
                    
                    return Some(AdaptationAction::Shrink {
                        old_size: current,
                        new_size,
                        utilization: utilization as usize,
                    });
                }
            }
        }
        
        None
    }

    pub fn current_size(&self) -> usize {
        self.current_size.load(Ordering::SeqCst)
    }

    pub fn utilization(&self) -> u64 {
        self.current_utilization.load(Ordering::SeqCst)
    }

    pub fn resize_count(&self) -> u64 {
        self.resize_count.load(Ordering::SeqCst)
    }

    pub fn force_resize(&self, new_size: usize) -> bool {
        if new_size >= self.min_size && new_size <= self.max_size {
            self.current_size.store(new_size, Ordering::SeqCst);
            self.resize_count.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    pub fn stats(&self) -> AdaptiveResourceStats {
        AdaptiveResourceStats {
            current_size: self.current_size.load(Ordering::SeqCst),
            min_size: self.min_size,
            max_size: self.max_size,
            utilization_percent: self.current_utilization.load(Ordering::SeqCst),
            resize_count: self.resize_count.load(Ordering::SeqCst),
            utilization_threshold: self.utilization_threshold,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AdaptationAction {
    Grow {
        old_size: usize,
        new_size: usize,
        utilization: usize,
    },
    Shrink {
        old_size: usize,
        new_size: usize,
        utilization: usize,
    },
}

#[derive(Debug, Clone)]
pub struct AdaptiveResourceStats {
    pub current_size: usize,
    pub min_size: usize,
    pub max_size: usize,
    pub utilization_percent: u64,
    pub resize_count: u64,
    pub utilization_threshold: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_resource_creation() {
        let mgr = AdaptiveResourceManager::new(100, 50, 500);
        assert_eq!(mgr.current_size(), 100);
    }

    #[test]
    fn test_adaptive_growth() {
        let mgr = AdaptiveResourceManager::with_config(100, 50, 500, 75, 1.5);
        
        if let Some(AdaptationAction::Grow { old_size, new_size, .. }) = 
            mgr.check_and_adapt(80, 0) {
            assert_eq!(old_size, 100);
            assert!(new_size > 100);
        }
    }

    #[test]
    fn test_adaptive_shrink() {
        let mgr = AdaptiveResourceManager::with_config(100, 50, 500, 75, 1.5);
        
        if let Some(AdaptationAction::Shrink { old_size, new_size, .. }) = 
            mgr.check_and_adapt(10, 0) {
            assert_eq!(old_size, 100);
            assert!(new_size < 100);
            assert!(new_size >= 50);
        }
    }

    #[test]
    fn test_adaptive_bounds() {
        let mgr = AdaptiveResourceManager::new(100, 50, 500);
        
        assert!(!mgr.force_resize(600));
        assert!(!mgr.force_resize(30));
        assert!(mgr.force_resize(200));
    }

    #[test]
    fn test_adaptive_stats() {
        let mgr = AdaptiveResourceManager::new(100, 50, 500);
        let stats = mgr.stats();
        assert_eq!(stats.current_size, 100);
        assert_eq!(stats.min_size, 50);
        assert_eq!(stats.max_size, 500);
    }
}
