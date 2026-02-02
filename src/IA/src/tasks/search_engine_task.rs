use alloc::collections::BTreeMap;
use crate::prelude::{String, Vec};

pub struct SearchEngine {
    documents: BTreeMap<u64, String>,
    inverted_index: BTreeMap<String, Vec<u64>>,
}

impl SearchEngine {
    pub fn new() -> Self {
        SearchEngine {
            documents: BTreeMap::new(),
            inverted_index: BTreeMap::new(),
        }
    }

    pub fn index_document(&mut self, doc_id: u64, content: String) {
        self.documents.insert(doc_id, content.clone());
        
        let words: Vec<&str> = content.split_whitespace().collect();
        for word in words {
            let word_lower = word.to_lowercase();
            self.inverted_index
                .entry(word_lower)
                .or_insert_with(Vec::new)
                .push(doc_id);
        }
    }

    pub fn search(&self, query: &str) -> Vec<u64> {
        let query_lower = query.to_lowercase();
        self.inverted_index
            .get(&query_lower)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_document(&self, doc_id: u64) -> Option<&String> {
        self.documents.get(&doc_id)
    }
}
