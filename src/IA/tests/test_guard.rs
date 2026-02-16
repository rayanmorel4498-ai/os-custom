#[cfg(test)]
extern crate std;

#[cfg(test)]
#[ctor::ctor]
fn enforce_test_mode() {
    let mode = std::env::var("IA_TEST_MODE").unwrap_or_else(|_| "hardware".to_string());
    if mode.eq_ignore_ascii_case("vm") {
        eprintln!("IA tests disabled on host (IA_TEST_MODE=vm). Run tests inside VM.");
        std::process::exit(0);
    }
    if !mode.eq_ignore_ascii_case("hardware") {
        eprintln!("IA_TEST_MODE must be 'hardware' or 'vm' (got {mode}).");
        std::process::exit(1);
    }
}
