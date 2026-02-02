use alloc::vec::Vec;
use alloc::vec;
use libm::sqrtf;

pub struct FaceModel {
    embedding_size: usize,
    histogram_bins: usize,
}

impl FaceModel {
    pub fn new() -> Self {
        FaceModel {
            embedding_size: 64,
            histogram_bins: 32,
        }
    }

    pub fn extract_features(&self, data: &[u8]) -> Vec<f32> {
        let mut features = Vec::with_capacity(self.embedding_size);
        let mut histogram = vec![0u32; self.histogram_bins];

        if data.is_empty() {
            return vec![0.0; self.embedding_size];
        }

        for &byte in data.iter() {
            let bin = (byte as usize * self.histogram_bins) / 256;
            histogram[bin.min(self.histogram_bins - 1)] += 1;
        }

        let total = data.len() as f32;
        for count in histogram.iter() {
            features.push(*count as f32 / total);
        }

        let segment_count = self.embedding_size - self.histogram_bins;
        let segment_len = (data.len() / segment_count.max(1)).max(1);
        for i in 0..segment_count {
            let start = i * segment_len;
            let end = (start + segment_len).min(data.len());
            if start >= end {
                features.push(0.0);
                continue;
            }
            let mut acc = 0u32;
            for j in (start + 1)..end {
                let diff = if data[j] > data[j - 1] {
                    data[j] - data[j - 1]
                } else {
                    data[j - 1] - data[j]
                } as u32;
                acc += diff;
            }
            let denom = (end - start).max(1) as f32;
            features.push(acc as f32 / denom / 255.0);
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

impl Default for FaceModel {
    fn default() -> Self {
        Self::new()
    }
}
