use crate::prelude::Vec;
use alloc::vec;

pub struct VectorDB {
    vectors: Vec<Vec<f32>>,
    ids: Vec<u64>,
    hnsw: Option<HnswIndex>,
}

pub struct HnswIndex {
    m: usize,
    ef: usize,
    neighbors: Vec<Vec<usize>>,
}

impl VectorDB {
    pub fn new() -> Self {
        VectorDB {
            vectors: Vec::new(),
            ids: Vec::new(),
            hnsw: None,
        }
    }

    pub fn enable_hnsw(&mut self, m: usize, ef: usize) {
        self.hnsw = Some(HnswIndex {
            m: m.max(1),
            ef: ef.max(1),
            neighbors: Vec::new(),
        });
    }

    pub fn insert(&mut self, id: u64, vector: Vec<f32>) {
        self.ids.push(id);
        self.vectors.push(vector);

        let m = self.hnsw.as_ref().map(|idx| idx.m);
        if let Some(m) = m {
            let new_idx = self.vectors.len() - 1;
            let mut scored: Vec<(usize, f32)> = if new_idx > 0 {
                (0..new_idx)
                    .map(|i| (i, self.cosine_similarity(&self.vectors[new_idx], &self.vectors[i])))
                    .collect()
            } else {
                Vec::new()
            };
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));

            if let Some(index) = self.hnsw.as_mut() {
                index.neighbors.push(Vec::new());
                for (i, _) in scored.into_iter().take(m) {
                    index.neighbors[new_idx].push(i);
                    index.neighbors[i].push(new_idx);
                }
            }
        }
    }

    pub fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = libm::sqrtf(a.iter().map(|x| x * x).sum::<f32>());
        let norm_b: f32 = libm::sqrtf(b.iter().map(|x| x * x).sum::<f32>());
        
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }

    pub fn search(&self, query: &[f32], top_k: usize) -> Vec<(u64, f32)> {
        if let Some(index) = &self.hnsw {
            if let Some(results) = self.search_hnsw(query, top_k, index) {
                return results;
            }
        }

        let mut results: Vec<(u64, f32)> = self.vectors
            .iter()
            .zip(self.ids.iter())
            .map(|(v, &id)| (id, self.cosine_similarity(query, v)))
            .collect();
        
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    fn search_hnsw(&self, query: &[f32], top_k: usize, index: &HnswIndex) -> Option<Vec<(u64, f32)>> {
        if self.vectors.is_empty() {
            return Some(Vec::new());
        }

        let mut visited = vec![false; self.vectors.len()];
        let mut candidates = Vec::new();
        candidates.push(0usize);

        for _ in 0..index.ef {
            let mut best_idx = None;
            let mut best_score = -1.0f32;
            for &c in candidates.iter() {
                if visited[c] {
                    continue;
                }
                let score = self.cosine_similarity(query, &self.vectors[c]);
                if score > best_score {
                    best_score = score;
                    best_idx = Some(c);
                }
            }

            let current = match best_idx {
                Some(idx) => idx,
                None => break,
            };

            visited[current] = true;
            for &n in index.neighbors.get(current).unwrap_or(&Vec::new()).iter() {
                if !visited[n] {
                    candidates.push(n);
                }
            }
        }

        let mut results: Vec<(u64, f32)> = visited
            .iter()
            .enumerate()
            .filter(|(_, v)| **v)
            .map(|(i, _)| (self.ids[i], self.cosine_similarity(query, &self.vectors[i])))
            .collect();

        if results.is_empty() {
            return None;
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        results.truncate(top_k);
        Some(results)
    }
}
