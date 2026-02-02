use spin::Mutex;
use crate::core::init::{with_resource_quota_mut, with_timekeeper};
use crate::r#loop::loop_manager::LoopState;

pub struct UtilityLoop {
    state: Mutex<LoopState>,
}

impl UtilityLoop {
    pub fn new() -> Self {
        UtilityLoop {
            state: Mutex::new(LoopState::new()),
        }
    }

    pub fn run(&self, timestamp_ms: u64) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        let now_ms = with_timekeeper(|tk| tk.now_ms()).unwrap_or(timestamp_ms);
        let _ = with_resource_quota_mut(|quota| quota.tick(now_ms));

        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed += 1;
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }
}

impl Default for UtilityLoop {
    fn default() -> Self {
        Self::new()
    }
}
