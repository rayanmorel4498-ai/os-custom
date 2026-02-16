use spin::Mutex;
use crate::core::init::{with_resource_quota_mut, with_timekeeper};
use crate::init::set_locked;
use crate::security::tls::bundle as tls_bundle;
use crate::r#loop::loop_manager::LoopState;
use crate::utils::{error::ErrorCode, logger};

const BUNDLE_REFRESH_INTERVAL_MS: u64 = 45_000;
const BUNDLE_REFRESH_WINDOW_MS: u64 = 5_000;
const IA_BUNDLE_TTL_SECS: u64 = 10;
const KERNEL_BUNDLE_TTL_SECS: u64 = 60;
const HARDWARE_BUNDLE_TTL_SECS: u64 = 30;

pub struct UtilityLoop {
    state: Mutex<LoopState>,
    last_bundle_refresh_ms: Mutex<u64>,
}

impl UtilityLoop {
    pub fn new() -> Self {
        UtilityLoop {
            state: Mutex::new(LoopState::new()),
            last_bundle_refresh_ms: Mutex::new(0),
        }
    }

    pub fn run(&self, timestamp_ms: u64) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        let now_ms = with_timekeeper(|tk| tk.now_ms()).unwrap_or(timestamp_ms);
        let _ = with_resource_quota_mut(|quota| quota.tick(now_ms));
        let mut should_lock = !tls_bundle::is_bundle_valid(now_ms);

        let should_refresh_periodic = {
            let last = *self.last_bundle_refresh_ms.lock();
            now_ms.saturating_sub(last) >= BUNDLE_REFRESH_INTERVAL_MS
        };
        if should_refresh_periodic {
            if tls_bundle::refresh_bundle_for_with_ttl("ia", now_ms, Some(IA_BUNDLE_TTL_SECS)).is_err() {
                logger::error("tls", ErrorCode::ErrUnavailable, "bundle refresh failed");
                should_lock = true;
            } else {
                let mut last = self.last_bundle_refresh_ms.lock();
                *last = now_ms;
            }
            if tls_bundle::refresh_bundle_for_with_ttl(
                "kernel",
                now_ms,
                Some(KERNEL_BUNDLE_TTL_SECS),
            )
            .is_err()
            {
                logger::warn("tls", ErrorCode::ErrUnavailable, "kernel bundle refresh failed");
            }
            if tls_bundle::refresh_bundle_for_with_ttl(
                "hardware",
                now_ms,
                Some(HARDWARE_BUNDLE_TTL_SECS),
            )
            .is_err()
            {
                logger::warn("tls", ErrorCode::ErrUnavailable, "hardware bundle refresh failed");
            }
        } else if tls_bundle::refresh_if_needed_for_with_ttl(
            "ia",
            now_ms,
            BUNDLE_REFRESH_WINDOW_MS,
            Some(IA_BUNDLE_TTL_SECS),
        )
        .is_err()
        {
            logger::error("tls", ErrorCode::ErrUnavailable, "bundle refresh failed");
            should_lock = true;
        } else {
            if tls_bundle::refresh_if_needed_for_with_ttl(
                "kernel",
                now_ms,
                BUNDLE_REFRESH_WINDOW_MS,
                Some(KERNEL_BUNDLE_TTL_SECS),
            )
            .is_err()
            {
                logger::warn("tls", ErrorCode::ErrUnavailable, "kernel bundle refresh failed");
            }
            if tls_bundle::refresh_if_needed_for_with_ttl(
                "hardware",
                now_ms,
                BUNDLE_REFRESH_WINDOW_MS,
                Some(HARDWARE_BUNDLE_TTL_SECS),
            )
            .is_err()
            {
                logger::warn("tls", ErrorCode::ErrUnavailable, "hardware bundle refresh failed");
            }
        }

        if should_lock {
            set_locked(true);
        } else if tls_bundle::is_bundle_valid(now_ms) {
            set_locked(false);
        }

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
