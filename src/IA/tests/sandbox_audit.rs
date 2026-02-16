mod test_guard;

use std::collections::BTreeMap as HashMap;
use std::sync::Arc;
use redmi_ia::security::sandbox::controller_enforced::{ActionType, SandboxController};
use redmi_ia::security::sandbox::gateway::SandboxGateway;

#[tokio::test]
async fn sandbox_audit_trail_reports_denied_action() {
	let sandbox = Arc::new(SandboxController::new());
	let gateway = SandboxGateway::new(Arc::clone(&sandbox));
	let mut params = HashMap::new();
	params.insert("module".into(), "ui".into());
	let _ = sandbox
		.validate_action(ActionType::KernelReboot, params)
		.await
		.err();
	let audit = gateway.get_denied_actions().await;
	assert!(!audit.is_empty());
}
