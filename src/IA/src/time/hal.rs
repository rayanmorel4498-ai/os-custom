use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub type HwTimerFn = fn() -> u64;

static HW_TIMER_FN: Mutex<Option<HwTimerFn>> = Mutex::new(None);
static FALLBACK_TICKS: AtomicU64 = AtomicU64::new(0);

/// Enregistre un timer HW si disponible.
pub fn set_hw_timer(timer: HwTimerFn) {
	*HW_TIMER_FN.lock() = Some(timer);
}

#[cfg(feature = "hw_timer")]
pub fn set_hw_timer_from_platform() {
	extern "C" {
		fn hw_timer_now_ms() -> u64;
	}
	unsafe {
		set_hw_timer(hw_timer_now_ms);
	}
}

pub fn is_hw_timer_set() -> bool {
	HW_TIMER_FN.lock().is_some()
}

/// Retourne le temps monotonic en ms depuis un timer HW si fourni,
/// sinon fallback std ou compteur interne no_std.
pub fn now_ms() -> u64 {
	if let Some(timer) = *HW_TIMER_FN.lock() {
		return timer();
	}
	FALLBACK_TICKS.fetch_add(1, Ordering::Relaxed)
}
