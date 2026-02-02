use alloc::vec::Vec;
use alloc::vec;
use libm::sqrtf;

pub struct FingerprintModel {
    embedding_size: usize,
    block_size: usize,
}

impl FingerprintModel {
    pub fn new() -> Self {
        FingerprintModel {
            embedding_size: 64,
            block_size: 32,
        }
    }

    pub fn extract_features(&self, data: &[u8]) -> Vec<f32> {
        if data.is_empty() {
            return vec![0.0; self.embedding_size];
        }

        let mut gradients = Vec::new();
        let mut idx = 1usize;
        while idx < data.len() {
            let diff = if data[idx] > data[idx - 1] {
                data[idx] - data[idx - 1]
            } else {
                data[idx - 1] - data[idx]
            };
            gradients.push(diff as f32 / 255.0);
            idx += 1;
        }

        let mut features = Vec::with_capacity(self.embedding_size);
        let blocks = self.embedding_size;
        let segment = (gradients.len() / blocks.max(1)).max(1);
        for i in 0..blocks {
            let start = i * segment;
            let end = (start + segment).min(gradients.len());
            if start >= end {
                features.push(0.0);
                continue;
            }
            let mut sum = 0.0f32;
            let mut energy = 0.0f32;
            for v in &gradients[start..end] {
                sum += *v;
                energy += *v * *v;
            }
            let denom = (end - start) as f32;
            let mean = sum / denom;
            let rms = sqrtf(energy / denom);
            features.push((mean + rms) * 0.5);
        }

        self.normalize(features)
    }

    pub fn similarity(&self, a: &[u8], b: &[u8]) -> f32 {
        let va = self.extract_features(a);
        let vb = self.extract_features(b);
        cosine_similarity(&va, &vb)
    }

    fn normalize(&self, mut v: Vec<f32>) -> Vec<f32> {
        let mut sum = 0.0f32;
        for &x in v.iter() {
            sum += x * x;
        }
        let norm = sqrtf(sum).max(1e-6);
        for x in v.iter_mut() {
            *x /= norm;
        }
        v
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut mag_a = 0.0f32;
    let mut mag_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        mag_a += a[i] * a[i];
        mag_b += b[i] * b[i];
    }
    let denom = sqrtf(mag_a * mag_b).max(1e-6);
    (dot / denom).min(1.0).max(0.0)
}

impl Default for FingerprintModel {
    fn default() -> Self {
        Self::new()
    }
}
