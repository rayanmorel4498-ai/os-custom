use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::{String, Vec};

pub struct DatabaseEngine {
    tables: Arc<Mutex<BTreeMap<String, BTreeMap<u64, Vec<u8>>>>>,
}

impl DatabaseEngine {
    pub fn new() -> Self {
        DatabaseEngine {
            tables: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn create_table(&self, table_name: String) {
        let mut tables = self.tables.lock();
        tables.insert(table_name, BTreeMap::new());
    }

    pub fn insert(&self, table: &str, key: u64, value: Vec<u8>) {
        let mut tables = self.tables.lock();
        if let Some(table_data) = tables.get_mut(table) {
            table_data.insert(key, value);
        }
    }

    pub fn query(&self, table: &str, key: u64) -> Option<Vec<u8>> {
        let tables = self.tables.lock();
        tables.get(table).and_then(|t| t.get(&key).cloned())
    }

    pub fn delete(&self, table: &str, key: u64) {
        let mut tables = self.tables.lock();
        if let Some(table_data) = tables.get_mut(table) {
            table_data.remove(&key);
        }
    }
}
