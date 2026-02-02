use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::{String, Vec};

pub struct IndexEngine {
    indices: Arc<Mutex<BTreeMap<String, BTreeMap<String, Vec<u64>>>>>,
}

impl IndexEngine {
    pub fn new() -> Self {
        IndexEngine {
            indices: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn create_index(&self, name: String) {
        let mut indices = self.indices.lock();
        indices.insert(name, BTreeMap::new());
    }

    pub fn index(&self, index_name: &str, key: String, doc_id: u64) {
        let mut indices = self.indices.lock();
        if let Some(index) = indices.get_mut(index_name) {
            index.entry(key).or_insert_with(Vec::new).push(doc_id);
        }
    }

    pub fn search(&self, index_name: &str, key: &str) -> Vec<u64> {
        let indices = self.indices.lock();
        indices
            .get(index_name)
            .and_then(|idx| idx.get(key).cloned())
            .unwrap_or_default()
    }
}
