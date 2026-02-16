use alloc::sync::Arc;
use spin::Mutex;
use crate::prelude::Vec;

pub struct PipelineStage {
    input_buffer: Arc<Mutex<Vec<u8>>>,
    output_buffer: Arc<Mutex<Vec<u8>>>,
}

impl PipelineStage {
    pub fn new() -> Self {
        PipelineStage {
            input_buffer: Arc::new(Mutex::new(Vec::new())),
            output_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn process(&self, transform: impl Fn(&[u8]) -> Vec<u8>) {
        let input = self.input_buffer.lock();
        let output = transform(&input);
        *self.output_buffer.lock() = output;
    }

    pub fn set_input(&self, data: Vec<u8>) {
        *self.input_buffer.lock() = data;
    }

    pub fn get_output(&self) -> Vec<u8> {
        self.output_buffer.lock().clone()
    }
}

pub struct Pipeline {
    stages: Vec<PipelineStage>,
}

impl Pipeline {
    pub fn new(num_stages: usize) -> Self {
        let mut stages = Vec::new();
        for _ in 0..num_stages {
            stages.push(PipelineStage::new());
        }
        Pipeline { stages }
    }

    pub fn stage(&self, idx: usize) -> Option<&PipelineStage> {
        self.stages.get(idx)
    }

    pub fn num_stages(&self) -> usize {
        self.stages.len()
    }
}
