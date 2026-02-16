mod test_guard;

use redmi_ia::r#loop::module_loop::ModuleLoop;
use redmi_ia::modules::runtime::RuntimeServices;
use redmi_ia::core::sandbox_controller::ActionType;
use redmi_ia::modules::control::resource_quota::{AdmissionDecision, PriorityClass};
use redmi_ia::core::policy_engine::PolicyDecision;
use redmi_ia::core::ipc_bus::IpcBus;

struct MockRuntime;

impl RuntimeServices for MockRuntime {
	fn now_ms(&self, fallback: u64) -> u64 {
		fallback
	}

	fn policy_decision(&self, _key: &str) -> PolicyDecision {
		PolicyDecision::Allow
	}

	fn sandbox_validate_action(
		&self,
		_module: &str,
		_action: ActionType,
		_cpu_ms: u64,
		_ram_mb: u64,
		_io_ops: u64,
	) -> bool {
		true
	}

	fn quota_decision_and_record(
		&self,
		_module: &str,
		_priority: PriorityClass,
		_cpu_ms: u64,
		_gpu_ms: u64,
		_now_ms: u64,
	) -> AdmissionDecision {
		AdmissionDecision::Allow
	}

	fn degraded_override(&self, _module: &str, _now_ms: u64) -> Option<AdmissionDecision> {
		None
	}

	fn degraded_record(&self, _module: &str, _now_ms: u64, _decision: AdmissionDecision) {}

	fn request_restart(&self, _module: &str, _now_ms: u64) {}

	fn request_rollback(&self, _module: &str, _now_ms: u64) {}

	fn app_priority(&self, _app_id: &str) -> f32 {
		0.7
	}

	fn energy_pressure(&self) -> f32 {
		0.0
	}
}

#[test]
fn realtime_loop_stress_does_not_panic() {
	let loop_instance = ModuleLoop::new(MockRuntime);
	let bus = IpcBus::new();
	for tick in 0..1000u64 {
		loop_instance.run(tick, &bus);
	}
	let state = loop_instance.get_state();
	assert_eq!(state.iterations, 1000);
	assert!(state.processed >= 0);
}
