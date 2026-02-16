use alloc::vec::Vec;
use crate::utils::observability;
use crate::init::{is_locked, set_locked};
use crate::security::tls::bundle as tls_bundle;

pub const OP_EXPORT_METRICS: u16 = 9000;
pub const OP_EXPORT_HEALTH: u16 = 9001;

pub fn handle_export(opcode: u16) -> Option<Vec<u8>> {
	let now_ms = crate::time::now_ms();
	if is_locked() || !tls_bundle::is_bundle_valid(now_ms) {
		set_locked(true);
		return None;
	}
	match opcode {
		OP_EXPORT_METRICS => Some(observability::export_metrics().into_bytes()),
		OP_EXPORT_HEALTH => Some(observability::export_health().into_bytes()),
		_ => None,
	}
}
