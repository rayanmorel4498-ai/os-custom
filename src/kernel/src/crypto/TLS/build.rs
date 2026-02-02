use std::env;

fn main() {
    let master_key = env::var("REDMI_MASTER_KEY").unwrap_or_default();
    let session_key = env::var("REDMI_SESSION_KEY").unwrap_or_default();
    let hardware_binding_secret = env::var("REDMI_HARDWARE_BINDING_SECRET").unwrap_or_default();
    let kernel_seed = env::var("REDMI_KERNEL_SEED").unwrap_or_default();
    let network_firewall_secret = env::var("REDMI_NETWORK_FIREWALL_SECRET").unwrap_or_default();
    let internal_api_secret = env::var("REDMI_INTERNAL_API_SECRET").unwrap_or_default();
    let integrity_check_secret = env::var("REDMI_INTEGRITY_CHECK_SECRET").unwrap_or_default();

    println!("cargo:rustc-env=REDMI_MASTER_KEY={}", master_key);
    println!("cargo:rustc-env=REDMI_SESSION_KEY={}", session_key);
    println!("cargo:rustc-env=REDMI_HARDWARE_BINDING_SECRET={}", hardware_binding_secret);
    println!("cargo:rustc-env=REDMI_KERNEL_SEED={}", kernel_seed);
    println!("cargo:rustc-env=REDMI_NETWORK_FIREWALL_SECRET={}", network_firewall_secret);
    println!("cargo:rustc-env=REDMI_INTERNAL_API_SECRET={}", internal_api_secret);
    println!("cargo:rustc-env=REDMI_INTEGRITY_CHECK_SECRET={}", integrity_check_secret);
}
