use redmi_ia::core::timekeeper::Timekeeper;

#[test]
fn timekeeper_rtc_sync_updates_time() {
    let mut tk = Timekeeper::new();
    tk.set_rtc_sync_interval_ms(1);
    let _ = tk.update_time_ms(1_000);
    tk.maybe_sync_rtc(Some(1_500));
    assert!(tk.now_ms() >= 1_000);
}
