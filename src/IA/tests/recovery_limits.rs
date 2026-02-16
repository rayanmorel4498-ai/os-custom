mod test_guard;
use redmi_ia::modules::recovery::auto_repair::AutoRepair;
use redmi_ia::utils::error::ErrorCode;

static mut RESTART_COUNT: u32 = 0;

fn restart_hook() -> bool {
    unsafe {
        RESTART_COUNT = RESTART_COUNT.saturating_add(1);
    }
    true
}

#[test]
fn recovery_restart_rate_limit() {
    let mut repair = AutoRepair::new();
    repair.set_restart_limits(2, 1000);
    repair.register_module_restart("mod", restart_hook);

    assert!(repair.restart_module("mod", 0).is_ok());
    assert!(repair.restart_module("mod", 10).is_ok());
    let third = repair.restart_module("mod", 20);
    assert_eq!(third.unwrap_err(), ErrorCode::ErrBusy);
}

#[test]
fn recovery_rollback_without_snapshot() {
    let mut repair = AutoRepair::new();
    let res = repair.rollback_config(0);
    assert_eq!(res.unwrap_err(), ErrorCode::ErrNotFound);
}
