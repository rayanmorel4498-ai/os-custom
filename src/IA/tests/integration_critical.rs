use redmi_ia::core::ai_core::AICore;

#[test]
fn integration_run_loops_safe_ai() {
    let core = AICore::new();
    core.run_loops(1_000);
}

#[test]
fn integration_run_loops_multiple_ticks() {
    let core = AICore::new();
    for t in [1000u64, 2000, 3000, 4000] {
        core.run_loops(t);
    }
}
