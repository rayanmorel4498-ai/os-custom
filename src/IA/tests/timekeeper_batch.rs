mod test_guard;
use redmi_ia::core::timekeeper::Timekeeper;

#[test]
fn timekeeper_cached_now() {
    let tk = Timekeeper::new();
    let _ = tk.update_time_ms(100);
    assert_eq!(tk.now_ms_cached(), 100);
}
