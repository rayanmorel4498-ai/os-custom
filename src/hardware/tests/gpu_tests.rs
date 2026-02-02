mod mock_gpu {
    pub mod gpu_control {
        pub fn init() -> Result<(), &'static str> { Ok(()) }
    }
    pub mod gpu_frequency {
        pub fn set_frequency(_freq: u32) -> Result<(), &'static str> { Ok(()) }
    }
}
use mock_gpu as gpu;

#[test]
fn test_gpu_initialization() {
    gpu::gpu_control::init().expect("Init failed");
}

#[test]
fn test_gpu_frequency_scaling() {
    for freq in &[160, 260, 400, 600, 800] {
        gpu::gpu_frequency::set_frequency(*freq).expect("Freq failed");
    }
}
