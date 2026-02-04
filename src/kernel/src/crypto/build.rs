use std::env;

fn main() {
    let _master_key = env::var("REDMI_MASTER_KEY").unwrap_or_default();
    let _session_key = env::var("REDMI_SESSION_KEY").unwrap_or_default();
    let _hardware_binding_secret = env::var("REDMI_HARDWARE_BINDING_SECRET").unwrap_or_default();
    let _kernel_seed = env::var("REDMI_KERNEL_SEED").unwrap_or_default();
    let _network_firewall_secret = env::var("REDMI_NETWORK_FIREWALL_SECRET").unwrap_or_default();
    let _internal_api_secret = env::var("REDMI_INTERNAL_API_SECRET").unwrap_or_default();
    let _integrity_check_secret = env::var("REDMI_INTEGRITY_CHECK_SECRET").unwrap_or_default();
}
