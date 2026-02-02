pub struct RedmiConfig;

impl RedmiConfig {
    pub fn get_master_key() -> &'static str { env!("REDMI_MASTER_KEY") }
    pub fn get_session_key() -> &'static str { env!("REDMI_SESSION_KEY") }
    pub fn get_hardware_binding_secret() -> &'static str { env!("REDMI_HARDWARE_BINDING_SECRET") }
    pub fn get_kernel_seed() -> &'static str { env!("REDMI_KERNEL_SEED") }
    pub fn get_network_firewall_secret() -> &'static str { env!("REDMI_NETWORK_FIREWALL_SECRET") }
    pub fn get_internal_api_secret() -> &'static str { env!("REDMI_INTERNAL_API_SECRET") }
    pub fn get_integrity_check_secret() -> &'static str { env!("REDMI_INTEGRITY_CHECK_SECRET") }
}

pub fn get_primary_loop_key() -> &'static str {
    RedmiConfig::get_master_key()
}

pub fn get_secondary_loop_key() -> &'static str {
    RedmiConfig::get_session_key()
}

pub fn get_third_loop_key() -> &'static str {
    RedmiConfig::get_session_key()
}

pub fn get_forth_loop_key() -> &'static str {
    RedmiConfig::get_hardware_binding_secret()
}

pub fn get_external_loop_key() -> &'static str {
    RedmiConfig::get_network_firewall_secret()
}

pub fn get_kernel_key() -> &'static str {
    RedmiConfig::get_kernel_seed()
}

pub fn get_api_key() -> &'static str {
    RedmiConfig::get_internal_api_secret()
}

pub fn get_integrity_key() -> &'static str {
    RedmiConfig::get_integrity_check_secret()
}
