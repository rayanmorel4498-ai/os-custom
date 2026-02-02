use alloc::vec::Vec;
use alloc::vec;
use libm::sqrtf;

pub struct VoiceModel {
    embedding_size: usize,
    frame_size: usize,
}

impl VoiceModel {
    pub fn new() -> Self {
        VoiceModel {
            embedding_size: 64,
            frame_size: 64,
        }
    }

    pub fn extract_features(&self, data: &[u8]) -> Vec<f32> {
        if data.is_empty() {
            return vec![0.0; self.embedding_size];
        }

        let mut energy = Vec::new();
        let mut zcr = Vec::new();

        let mut idx = 0usize;
        while idx < data.len() {
            let end = (idx + self.frame_size).min(data.len());
            let frame = &data[idx..end];
            let mut e = 0.0f32;
            let mut crossings = 0u32;
            let mut prev = frame[0] as i16 - 128;
            for &b in frame.iter() {
                let sample = b as i16 - 128;
                let fs = sample as f32 / 128.0;
                e += fs * fs;
                if (sample >= 0 && prev < 0) || (sample < 0 && prev >= 0) {
                    crossings += 1;
                }
                prev = sample;
            }
            let denom = frame.len().max(1) as f32;
            energy.push(e / denom);
            zcr.push(crossings as f32 / denom);
            idx += self.frame_size;
        }

        let mut features = Vec::with_capacity(self.embedding_size);
        let energy_bins = self.embedding_size / 2;
        let zcr_bins = self.embedding_size - energy_bins;

        features.extend(self.downsample(&energy, energy_bins));
        features.extend(self.downsample(&zcr, zcr_bins));

        self.normalize(features)
    }

    pub fn similarity(&self, a: &[u8], b: &[u8]) -> f32 {
        let va = self.extract_features(a);
        let vb = self.extract_features(b);
        cosine_similarity(&va, &vb)
    }

    fn downsample(&self, data: &[f32], bins: usize) -> Vec<f32> {
        if data.is_empty() {
            return vec![0.0; bins];
        }
        let mut out = Vec::with_capacity(bins);
        let segment = (data.len() / bins.max(1)).max(1);
        for i in 0..bins {
            let start = i * segment;
            let end = (start + segment).min(data.len());
            if start >= end {
                out.push(0.0);
                continue;
            }
            let mut sum = 0.0f32;
            for v in &data[start..end] {
                sum += *v;
            }
            out.push(sum / (end - start) as f32);
        }
        out
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

impl Default for VoiceModel {
    fn default() -> Self {
        Self::new()
    }
}
