use redmi_ia::core::timekeeper::Timekeeper;

#[test]
fn timekeeper_clamps_jumps() {
    let mut tk = Timekeeper::new();
    tk.set_max_jump_ms(100);
    let t1 = tk.update_time_ms(1_000);
    let t2 = tk.update_time_ms(5_000);
    assert_eq!(t1, 1_000);
    assert_eq!(t2, 1_100);
}

#[test]
fn timekeeper_monotonic_ticks() {
    let tk = Timekeeper::new();
    let t = tk.update_monotonic_ticks(1_000, 1_000);
    assert_eq!(t, 1_000);
}

#[test]
fn timekeeper_cache_and_drift() {
    let mut tk = Timekeeper::new();
    tk.set_cache_window_ms(10);
    let _ = tk.update_time_ms(1_000);
    let cached = tk.now_ms_cached();
    assert_eq!(cached, 1_000);
    tk.update_rtc_ms(1_050);
    assert!(tk.drift_ms_ema() >= 50.0);
}
