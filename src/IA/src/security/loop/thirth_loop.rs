use spin::Mutex;
use crate::core::tls_integration::TLSIntegrationManager;
use crate::r#loop::loop_manager::LoopState;

pub struct ThirthLoop {
    state: Mutex<LoopState>,
}

impl ThirthLoop {
    pub fn new() -> Self {
        ThirthLoop {
            state: Mutex::new(LoopState::new()),
        }
    }

    pub fn run(&self, timestamp_ms: u64, tls: &TLSIntegrationManager) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        tls.internal_loop_iteration();
        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed += 1;
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }
}

impl Default for ThirthLoop {
    fn default() -> Self {
        Self::new()
    }
}
