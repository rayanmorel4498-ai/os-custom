use spin::Mutex;
use crate::core::global_state::GlobalStateManager;
use crate::r#loop::loop_manager::LoopState;

pub struct ExternalLoop {
    state: Mutex<LoopState>,
}

impl ExternalLoop {
    pub fn new() -> Self {
        ExternalLoop {
            state: Mutex::new(LoopState {
                enabled: true,
                iterations: 0,
                last_tick_ms: 0,
                processed: 0,
            }),
        }
    }

    pub fn run(&self, timestamp_ms: u64, global_state: &GlobalStateManager) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        global_state.add_runtime(1000);
        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed += 1;
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }
}

impl Default for ExternalLoop {
    fn default() -> Self {
        Self::new()
    }
}
