mod test_guard;
use redmi_ia::core::adaptive_scheduler::{AdaptiveScheduler, WorkloadType};
use redmi_ia::core::local_profiler::ModuleUsage;
use std::collections::BTreeMap;

#[test]
fn adaptive_scheduler_over_budget() {
    let mut sched = AdaptiveScheduler::new();
    sched.set_hard_budget(1.0, 1.0, 1.0);
    let mut usage = BTreeMap::new();
    usage.insert(
        "m".into(),
        ModuleUsage {
            cpu_ms: 5,
            gpu_ms: 0,
            io_ms: 0,
            calls: 1,
        },
    );
    assert!(sched.is_over_budget(&usage));
    let choice = sched.recommend(&usage, WorkloadType::CPU);
    assert_eq!(choice, WorkloadType::GPU);
}
