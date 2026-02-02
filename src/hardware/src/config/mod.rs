extern crate alloc;

use core::str;

pub mod hardware_pool;
pub mod hardware_driver_service;

pub use self::hardware_pool::{
    CommandType, HardwareResponse, HardwareRequest, 
    HardwareCommandPool, HardwareDriver,
};
pub use self::hardware_driver_service::{
    HardwareDriverService, SecureMmioMapping,
};

#[derive(Debug, Clone, Copy)]
pub struct DeviceConfig {
    pub name: &'static str,
    pub model: &'static str,
    pub architecture: &'static str,
    pub android_version_base: &'static str,
    pub custom_os_version: &'static str,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HardwareRegisters {
    pub cpu_apcs_base: u64,
    pub cpu_big_pll_base: u64,
    pub cpu_big_freq_reg: u64,
    pub cpu_big_volt_reg: u64,
    pub cpu_little_pll_base: u64,
    pub cpu_little_freq_reg: u64,
    pub cpu_little_volt_reg: u64,
    pub cpu_core_ctrl_base: u64,

    pub gpio_base: u64,
    pub gpio_dir: u64,
    pub gpio_out: u64,
    pub gpio_in: u64,
    pub gpio_drive: u64,
    pub gpio_mode: u64,

    pub i2c_base: u64,

    pub uart_base: u64,

    pub pci_base: u64,
    pub pci_cfg_addr: u64,
    pub pci_cfg_data: u64,
    pub pci_status: u64,
    pub pci_ctrl: u64,

    pub usb_base: u64,
    pub usb_ctrl: u64,
    pub usb_status: u64,
    pub usb_speed: u64,
    pub usb_power: u64,

    pub spi_base: u64,
    pub spi_ctrl: u64,
    pub spi_status: u64,
    pub spi_tx: u64,
    pub spi_rx: u64,
    pub spi_clk: u64,

    pub gpu_freq_ctrl: u64,
    pub gpu_freq_status: u64,
    pub gpu_vram_base: u64,
    pub gpu_mem_ctrl: u64,
    pub gpu_mem_status: u64,
    pub gpu_base: u64,
    pub gpu_power_control: u64,
    pub gpu_reset_control: u64,
    pub gpu_clock_control: u64,
    pub gpu_status_reg: u64,
    pub gpu_command_reg: u64,
    pub gpu_frequency_reg: u64,
    pub gpu_interrupt_status: u64,
    pub gpu_interrupt_mask: u64,
    pub gpu_shader_cores_enable: u64,
    pub gpu_cores_status: u64,
    pub gpu_power_domain_0: u64,
    pub gpu_power_domain_1: u64,
    pub gpu_power_domain_2: u64,
    pub gpu_power_domain_3: u64,
    pub gpu_power_ctrl: u64,
    pub gpu_power_status: u64,
    pub gpu_security_base: u32,
    pub gpu_cmd_base: u64,
    pub gpu_cmd_status: u64,
    pub gpu_cmd_fence: u64,

    pub ddr_phy_base: u64,
    pub memc_base: u64,
    pub ddr_axi_base: u64,
    pub phy_freq_reg: u64,
    pub phy_status_reg: u64,
    pub phy_mode_reg: u64,
    pub phy_timing_reg: u64,
    pub phy_voltage_reg: u64,
    pub phy_power_reg: u64,
    pub phy_security_ctrl: u64,
    pub phy_security_status: u64,
    pub memc_ctrl_reg: u64,
    pub memc_status_reg: u64,
    pub memc_freq_reg: u64,
    pub memc_refresh_reg: u64,
    pub memc_timing_reg: u64,
    pub memc_lock_ctrl: u64,
    pub memc_erase_ctrl: u64,
    pub memc_debug_ctrl: u64,
    pub axi_config_reg: u64,
    pub axi_status_reg: u64,
    pub ram_base: u64,
    pub refresh_status: u64,
    pub refresh_timer: u64,
    pub refresh_interval: u64,
    pub refresh_ctrl: u64,
    pub ram_timing_ctrl: u64,

    pub power_base: u64,
    pub vdd_core: u64,
    pub vdd_gpu: u64,
    pub vdd_modem: u64,
    pub vdd_io: u64,

    pub display_ctrl_base: u64,
    pub display_ctrl: u64,
    pub display_status: u64,
    pub display_width: u64,
    pub display_height: u64,
    pub display_mode: u64,
    pub display_refresh: u64,
    pub display_config: u64,
    pub display_data: u64,

    pub screen_base: u64,
    pub screen_ctrl: u64,
    pub screen_status: u64,
    pub screen_width: u64,
    pub screen_height: u64,
    pub screen_refresh: u64,
    pub screen_brightness: u64,
    pub screen_config: u64,
    pub screen_data: u64,

    pub brightness_base: u64,
    pub brightness_ctrl: u64,
    pub brightness_status: u64,
    pub brightness_level: u64,
    pub brightness_min: u64,
    pub brightness_max: u64,
    pub brightness_config: u64,
    pub brightness_mode: u64,
    pub brightness_data: u64,

    pub fingerprint_base: u64,
    pub fingerprint_ctrl: u64,
    pub fingerprint_status: u64,
    pub fingerprint_enroll: u64,
    pub fingerprint_verify: u64,
    pub fingerprint_template: u64,
    pub fingerprint_attempts: u64,
    pub fingerprint_lock: u64,
    pub fingerprint_data: u64,

    pub iris_base: u64,
    pub iris_ctrl: u64,
    pub iris_status: u64,

    pub voice_base: u64,
    pub voice_ctrl: u64,
    pub voice_status: u64,

    pub faceid_base: u64,
    pub faceid_ctrl: u64,
    pub faceid_status: u64,
    pub faceid_enroll: u64,
    pub faceid_verify: u64,
    pub faceid_conf: u64,
    pub faceid_attempts: u64,
    pub faceid_lock: u64,
    pub faceid_data: u64,

    pub camera_ctrl_base: u64,
    pub camera_ctrl: u64,
    pub camera_status: u64,
    pub camera_select: u64,
    pub camera_power: u64,
    pub camera_reset: u64,
    pub camera_config: u64,
    pub camera_mode: u64,
    pub camera_data: u64,

    pub front_isp_base: u64,
    pub front_isp_ctrl: u64,
    pub front_isp_status: u64,
    pub front_isp_config: u64,
    pub front_isp_resolution: u64,
    pub front_isp_frame_rate: u64,
    pub front_isp_mode: u64,
    pub front_isp_format: u64,
    pub front_isp_data: u64,

    pub rear_isp_base: u64,
    pub rear_isp_ctrl: u64,
    pub rear_isp_status: u64,
    pub rear_isp_config: u64,
    pub rear_isp_resolution: u64,
    pub rear_isp_frame_rate: u64,
    pub rear_isp_mode: u64,
    pub rear_isp_format: u64,
    pub rear_isp_data: u64,

    pub flash_ctrl_base: u64,
    pub flash_ctrl: u64,
    pub flash_status: u64,
    pub flash_pwm: u64,
    pub flash_brightness: u64,
    pub flash_timing: u64,
    pub flash_mode: u64,
    pub flash_config: u64,
    pub flash_data: u64,

    pub zoom_ctrl_base: u64,
    pub zoom_ctrl: u64,
    pub zoom_status: u64,
    pub zoom_level: u64,
    pub zoom_max: u64,
    pub zoom_min: u64,
    pub zoom_config: u64,
    pub zoom_mode: u64,
    pub zoom_data: u64,

    pub stabilization_ctrl_base: u64,
    pub stabilization_ctrl: u64,
    pub stabilization_status: u64,
    pub stabilization_x_offset: u64,
    pub stabilization_y_offset: u64,
    pub stabilization_gain: u64,
    pub stabilization_config: u64,
    pub stabilization_mode: u64,
    pub stabilization_data: u64,

    pub depth_ctrl_base: u64,
    pub depth_ctrl: u64,
    pub depth_status: u64,
    pub depth_data: u64,
    pub depth_range: u64,
    pub depth_accuracy: u64,
    pub depth_config: u64,
    pub depth_mode: u64,
    pub depth_result: u64,

    pub nfc_base: u64,
    pub nfc_ctrl_reg: u64,
    pub nfc_status_reg: u64,
    pub nfc_interrupt_reg: u64,
    pub nfc_error_reg: u64,
    pub nfc_command_reg: u64,
    pub nfc_response_reg: u64,
    pub nfc_fifo_reg: u64,
    pub nfc_timeout_reg: u64,
    pub nfc_config_reg: u64,
    pub nfc_mode_reg: u64,

    pub payment_ctrl_reg: u64,
    pub payment_status_reg: u64,
    pub payment_amount_reg: u64,
    pub payment_currency_reg: u64,
    pub payment_security_reg: u64,
    pub payment_log_reg: u64,
    pub payment_config_reg: u64,

    pub reader_config_reg: u64,
    pub reader_detect_reg: u64,
    pub uid_reg: u64,
    pub whitelist_reg: u64,

    pub writer_config_reg: u64,
    pub writer_erase_reg: u64,
    pub write_data_reg: u64,
    pub write_addr_reg: u64,

    pub audio_base: u64,
    pub audio_codec_base: u64,
    pub speaker_base: u64,
    pub microphone_base: u64,
    pub headphone_jack_base: u64,
    pub noise_cancellation_base: u64,
    pub audio_input_base: u64,

    pub gnss_ctrl_base: u64,
    pub gnss_ctrl: u64,
    pub gnss_status: u64,
    pub gnss_lat: u64,
    pub gnss_lon: u64,
    pub gnss_alt: u64,
    pub gnss_config: u64,
    pub gnss_mode: u64,
    pub gnss_data: u64,

    pub geo_ctrl_base: u64,
    pub geo_ctrl: u64,
    pub geo_status: u64,
    pub geo_lat: u64,
    pub geo_lon: u64,
    pub geo_radius: u64,
    pub geo_config: u64,
    pub geo_mode: u64,
    pub geo_data: u64,

    pub loc_ctrl_base: u64,
    pub loc_ctrl: u64,
    pub loc_status: u64,
    pub loc_lat: u64,
    pub loc_lon: u64,
    pub loc_alt: u64,
    pub loc_config: u64,
    pub loc_mode: u64,
    pub loc_data: u64,

    pub bt_base: u64,
    pub bt_ctrl: u64,
    pub bt_status: u64,
    pub bt_freq: u64,
    pub bt_band: u64,

    pub wifi_base: u64,
    pub wifi_ctrl: u64,
    pub wifi_status: u64,
    pub wifi_freq: u64,
    pub wifi_channel: u64,

    pub lte_base: u64,
    pub fiveg_base: u64,
    pub gsm_base: u64,
    pub esim_base: u64,
    pub sim_base: u64,
    pub satellite_base: u64,
    pub zigbee_base: u64,
    pub thread_base: u64,

    pub key_storage_base: u64,
    pub key_ctrl: u64,
    pub key_status: u64,
    pub key_addr: u64,
    pub key_size: u64,
    pub key_config: u64,
    pub key_mode: u64,
    pub key_lock: u64,
    pub key_data: u64,

    pub pmic_chg_ctrl: u8,
    pub pmic_chg_status: u8,
    pub pmic_chg_current: u8,
    pub pmic_chg_voltage: u8,

    pub battery_i2c_addr: u8,
    pub battery_reg_voltage: u8,
    pub battery_reg_current: u8,
    pub battery_reg_soc: u8,
    pub battery_reg_status: u8,
}

impl HardwareRegisters {
    pub fn default_redmi_15c() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityConfig {
    pub level: u8,
    pub encryption: &'static str,
    pub secure_boot: bool,
    pub verified_boot: bool,
    pub secure_element: bool,
    pub tee_enabled: bool,
    pub anti_tamper: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BiometricConfig {
    pub fingerprint: bool,
    pub face_id: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CPUConfig {
    pub max_frequency: u32,
    pub min_frequency: u32,
    pub turbo_enabled: bool,
    pub cores: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct GPUConfig {
    pub max_frequency: u32,
    pub throttle_temperature: i8,
    pub memory_mb: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct RAMConfig {
    pub size_mb: u32,
    pub frequency: u32,
    pub timing_cl: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct ThermalConfig {
    pub critical_temp: i8,
    pub throttle_temp: i8,
    pub warning_temp: i8,
}

#[derive(Debug, Clone, Copy)]
pub struct PowerConfig {
    pub battery_capacity_mah: u32,
    pub fast_charging_enabled: bool,
    pub wireless_charging_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DisplayConfig {
    pub resolution_width: u16,
    pub resolution_height: u16,
    pub refresh_rate: u8,
    pub brightness_max: u8,
}

#[derive(Clone, Copy)]
pub struct HardwareConfig {
    pub device: DeviceConfig,
    pub security: SecurityConfig,
    pub biometric: BiometricConfig,
    pub cpu: CPUConfig,
    pub gpu: GPUConfig,
    pub ram: RAMConfig,
    pub thermal: ThermalConfig,
    pub power: PowerConfig,
    pub display: DisplayConfig,
    pub registers: HardwareRegisters,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self::default_redmi_15c()
    }
}

impl HardwareConfig {
    pub fn default_redmi_15c() -> Self {
        Self {
            device: DeviceConfig {
                name: "Redmi-15c",
                model: "xiaomi-redmi-15c",
                architecture: "arm64",
                android_version_base: "14",
                custom_os_version: "2.0-Advanced",
            },
            security: SecurityConfig {
                level: 5,
                encryption: "AES-256-CTR",
                secure_boot: true,
                verified_boot: true,
                secure_element: true,
                tee_enabled: true,
                anti_tamper: true,
            },
            biometric: BiometricConfig {
                fingerprint: true,
                face_id: true,
            },
            cpu: CPUConfig {
                max_frequency: 3000,
                min_frequency: 800,
                turbo_enabled: true,
                cores: 8,
            },
            gpu: GPUConfig {
                max_frequency: 850,
                throttle_temperature: 80,
                memory_mb: 6144,
            },
            ram: RAMConfig {
                size_mb: 12288,
                frequency: 2400,
                timing_cl: 16,
            },
            thermal: ThermalConfig {
                critical_temp: 95,
                throttle_temp: 85,
                warning_temp: 75,
            },
            power: PowerConfig {
                battery_capacity_mah: 5000,
                fast_charging_enabled: true,
                wireless_charging_enabled: true,
            },
            display: DisplayConfig {
                resolution_width: 1440,
                resolution_height: 3200,
                refresh_rate: 120,
                brightness_max: 100,
            },
            registers: HardwareRegisters::default(),
        }
    }

    pub fn init() -> Self {
        let mut cfg = Self::default_redmi_15c();
        apply_yaml_overrides(&mut cfg);
        cfg
    }
}

static mut GLOBAL_CONFIG: Option<HardwareConfig> = None;

pub fn get_config() -> HardwareConfig {
    unsafe {
        GLOBAL_CONFIG.unwrap_or(HardwareConfig::init())
    }
}

pub unsafe fn set_config(config: HardwareConfig) {
    GLOBAL_CONFIG = Some(config);
}

pub fn init_config() {
    unsafe {
        let config_ptr = core::ptr::addr_of_mut!(GLOBAL_CONFIG);
        if (*config_ptr).is_none() {
            *config_ptr = Some(HardwareConfig::init());
        }
    }
}

const PHY_FREQ_OFFSET: u64 = 0x0000;
const PHY_STATUS_OFFSET: u64 = 0x0004;
const PHY_MODE_OFFSET: u64 = 0x0008;
const PHY_TIMING_OFFSET: u64 = 0x000C;
const PHY_VOLTAGE_OFFSET: u64 = 0x0010;
const PHY_POWER_OFFSET: u64 = 0x0014;
const PHY_SECURITY_CTRL_OFFSET: u64 = 0x0020;
const PHY_SECURITY_STATUS_OFFSET: u64 = 0x0024;

const GPIO_DIR_OFFSET: u64 = 0x0000;
const GPIO_OUT_OFFSET: u64 = 0x0004;
const GPIO_IN_OFFSET: u64 = 0x0008;
const GPIO_DRIVE_OFFSET: u64 = 0x000C;
const GPIO_MODE_OFFSET: u64 = 0x0010;

const I2C_BASE_OFFSET: u64 = 0x0000;

const UART_BASE_OFFSET: u64 = 0x0000;

const PCI_CFG_ADDR_OFFSET: u64 = 0x0000;
const PCI_CFG_DATA_OFFSET: u64 = 0x0004;
const PCI_STATUS_OFFSET: u64 = 0x0008;
const PCI_CTRL_OFFSET: u64 = 0x000C;

const USB_CTRL_OFFSET: u64 = 0x0000;
const USB_STATUS_OFFSET: u64 = 0x0004;
const USB_SPEED_OFFSET: u64 = 0x0008;
const USB_POWER_OFFSET: u64 = 0x000C;

const SPI_CTRL_OFFSET: u64 = 0x0000;
const SPI_STATUS_OFFSET: u64 = 0x0004;
const SPI_TX_OFFSET: u64 = 0x0008;
const SPI_RX_OFFSET: u64 = 0x000C;
const SPI_CLK_OFFSET: u64 = 0x0010;

const MEMC_CTRL_OFFSET: u64 = 0x0000;
const MEMC_STATUS_OFFSET: u64 = 0x0004;
const MEMC_FREQ_OFFSET: u64 = 0x0008;
const MEMC_REFRESH_OFFSET: u64 = 0x000C;
const MEMC_TIMING_OFFSET: u64 = 0x0010;
const REFRESH_STATUS_OFFSET: u64 = 0x0040;
const REFRESH_TIMER_OFFSET: u64 = 0x0044;
const REFRESH_INTERVAL_OFFSET: u64 = 0x0048;
const MEMC_LOCK_OFFSET: u64 = 0x0050;
const MEMC_ERASE_OFFSET: u64 = 0x0054;
const MEMC_DEBUG_OFFSET: u64 = 0x0058;

const DISPLAY_CTRL_OFFSET: u64 = 0x0000;
const DISPLAY_STATUS_OFFSET: u64 = 0x0004;
const DISPLAY_WIDTH_OFFSET: u64 = 0x0008;
const DISPLAY_HEIGHT_OFFSET: u64 = 0x000C;
const DISPLAY_MODE_OFFSET: u64 = 0x0010;
const DISPLAY_REFRESH_OFFSET: u64 = 0x0014;
const DISPLAY_CONFIG_OFFSET: u64 = 0x0018;
const DISPLAY_DATA_OFFSET: u64 = 0x001C;

const BRIGHTNESS_CTRL_OFFSET: u64 = 0x0000;
const BRIGHTNESS_STATUS_OFFSET: u64 = 0x0004;
const BRIGHTNESS_LEVEL_OFFSET: u64 = 0x0008;
const BRIGHTNESS_MIN_OFFSET: u64 = 0x000C;
const BRIGHTNESS_MAX_OFFSET: u64 = 0x0010;
const BRIGHTNESS_CONFIG_OFFSET: u64 = 0x0014;
const BRIGHTNESS_MODE_OFFSET: u64 = 0x0018;
const BRIGHTNESS_DATA_OFFSET: u64 = 0x001C;

const SCREEN_CTRL_OFFSET: u64 = 0x0000;
const SCREEN_STATUS_OFFSET: u64 = 0x0004;
const SCREEN_WIDTH_OFFSET: u64 = 0x0008;
const SCREEN_HEIGHT_OFFSET: u64 = 0x000C;
const SCREEN_REFRESH_OFFSET: u64 = 0x0010;
const SCREEN_BRIGHTNESS_OFFSET: u64 = 0x0014;
const SCREEN_CONFIG_OFFSET: u64 = 0x0018;
const SCREEN_DATA_OFFSET: u64 = 0x001C;

const CAMERA_CTRL_OFFSET: u64 = 0x0000;
const CAMERA_STATUS_OFFSET: u64 = 0x0004;
const CAMERA_SELECT_OFFSET: u64 = 0x0008;
const CAMERA_POWER_OFFSET: u64 = 0x000C;
const CAMERA_RESET_OFFSET: u64 = 0x0010;
const CAMERA_CONFIG_OFFSET: u64 = 0x0014;
const CAMERA_MODE_OFFSET: u64 = 0x0018;
const CAMERA_DATA_OFFSET: u64 = 0x001C;

const ISP_CTRL_OFFSET: u64 = 0x0000;
const ISP_STATUS_OFFSET: u64 = 0x0004;
const ISP_CONFIG_OFFSET: u64 = 0x0008;
const ISP_RESOLUTION_OFFSET: u64 = 0x000C;
const ISP_FRAME_RATE_OFFSET: u64 = 0x0010;
const ISP_MODE_OFFSET: u64 = 0x0014;
const ISP_FORMAT_OFFSET: u64 = 0x0018;
const ISP_DATA_OFFSET: u64 = 0x001C;

const NFC_CTRL_OFFSET: u64 = 0x0000;
const NFC_STATUS_OFFSET: u64 = 0x0004;
const NFC_INTERRUPT_OFFSET: u64 = 0x0008;
const NFC_ERROR_OFFSET: u64 = 0x000C;
const NFC_COMMAND_OFFSET: u64 = 0x0010;
const NFC_RESPONSE_OFFSET: u64 = 0x0014;
const NFC_FIFO_OFFSET: u64 = 0x0018;
const NFC_TIMEOUT_OFFSET: u64 = 0x001C;
const NFC_CONFIG_OFFSET: u64 = 0x0020;
const NFC_MODE_OFFSET: u64 = 0x0024;

const READER_CONFIG_OFFSET: u64 = 0x0030;
const READER_DETECT_OFFSET: u64 = 0x0034;
const UID_OFFSET: u64 = 0x0038;
const WHITELIST_OFFSET: u64 = 0x003C;

const WRITER_CONFIG_OFFSET: u64 = 0x0040;
const WRITER_ERASE_OFFSET: u64 = 0x0044;
const WRITE_DATA_OFFSET: u64 = 0x0048;
const WRITE_ADDR_OFFSET: u64 = 0x004C;

const PAYMENT_CTRL_OFFSET: u64 = 0x0050;
const PAYMENT_STATUS_OFFSET: u64 = 0x0054;
const PAYMENT_AMOUNT_OFFSET: u64 = 0x0058;
const PAYMENT_CURRENCY_OFFSET: u64 = 0x005C;
const PAYMENT_SECURITY_OFFSET: u64 = 0x0060;
const PAYMENT_LOG_OFFSET: u64 = 0x0064;
const PAYMENT_CONFIG_OFFSET: u64 = 0x0068;

const AUDIO_CODEC_OFFSET: u64 = 0x0000;
const AUDIO_SPEAKER_OFFSET: u64 = 0x1000;
const AUDIO_MIC_OFFSET: u64 = 0x2000;
const AUDIO_JACK_OFFSET: u64 = 0x3000;
const AUDIO_ANC_OFFSET: u64 = 0x4000;
const AUDIO_INPUT_OFFSET: u64 = 0x5000;

const BT_CTRL_OFFSET: u64 = 0x0000;
const BT_STATUS_OFFSET: u64 = 0x0004;
const BT_FREQ_OFFSET: u64 = 0x0008;
const BT_BAND_OFFSET: u64 = 0x000C;

const WIFI_CTRL_OFFSET: u64 = 0x0000;
const WIFI_STATUS_OFFSET: u64 = 0x0004;
const WIFI_FREQ_OFFSET: u64 = 0x0008;
const WIFI_CHANNEL_OFFSET: u64 = 0x000C;

fn apply_yaml_overrides(cfg: &mut HardwareConfig) {
    if let Some(total_gb) = crate::yaml_get_u64(&["hardware", "ram", "total_gb"]) {
        cfg.ram.size_mb = (total_gb as u32).saturating_mul(1024);
    }

    if let Some(freq) = crate::yaml_get_u32(&["hardware", "ram", "frequency_mhz"]) {
        cfg.ram.frequency = freq;
    } else if let Some(freq) = crate::yaml_get_u32(&["hardware", "ram", "freq_mhz"]) {
        cfg.ram.frequency = freq;
    } else if let Some(freq) = crate::yaml_get_u32(&["hardware", "ram", "frequency"]) {
        cfg.ram.frequency = freq;
    }

    if let Some(ddr_phy_base) = crate::yaml_get_u64(&["mmio", "memory", "ddr_phy_base"]) {
        cfg.registers.ddr_phy_base = ddr_phy_base;
        cfg.registers.phy_freq_reg = ddr_phy_base + PHY_FREQ_OFFSET;
        cfg.registers.phy_status_reg = ddr_phy_base + PHY_STATUS_OFFSET;
        cfg.registers.phy_mode_reg = ddr_phy_base + PHY_MODE_OFFSET;
        cfg.registers.phy_timing_reg = ddr_phy_base + PHY_TIMING_OFFSET;
        cfg.registers.phy_voltage_reg = ddr_phy_base + PHY_VOLTAGE_OFFSET;
        cfg.registers.phy_power_reg = ddr_phy_base + PHY_POWER_OFFSET;
        cfg.registers.phy_security_ctrl = ddr_phy_base + PHY_SECURITY_CTRL_OFFSET;
        cfg.registers.phy_security_status = ddr_phy_base + PHY_SECURITY_STATUS_OFFSET;
    }

    if let Some(memc_base) = crate::yaml_get_u64(&["mmio", "memory", "memc_base"]) {
        cfg.registers.memc_base = memc_base;
        cfg.registers.memc_ctrl_reg = memc_base + MEMC_CTRL_OFFSET;
        cfg.registers.memc_status_reg = memc_base + MEMC_STATUS_OFFSET;
        cfg.registers.memc_freq_reg = memc_base + MEMC_FREQ_OFFSET;
        cfg.registers.memc_refresh_reg = memc_base + MEMC_REFRESH_OFFSET;
        cfg.registers.memc_timing_reg = memc_base + MEMC_TIMING_OFFSET;
        cfg.registers.refresh_status = memc_base + REFRESH_STATUS_OFFSET;
        cfg.registers.refresh_timer = memc_base + REFRESH_TIMER_OFFSET;
        cfg.registers.refresh_interval = memc_base + REFRESH_INTERVAL_OFFSET;
        cfg.registers.memc_lock_ctrl = memc_base + MEMC_LOCK_OFFSET;
        cfg.registers.memc_erase_ctrl = memc_base + MEMC_ERASE_OFFSET;
        cfg.registers.memc_debug_ctrl = memc_base + MEMC_DEBUG_OFFSET;
    }

    if let Some(gpio_base) = crate::yaml_get_u64(&["mmio", "gpio", "base"]) {
        cfg.registers.gpio_base = gpio_base;
        cfg.registers.gpio_dir = gpio_base + GPIO_DIR_OFFSET;
        cfg.registers.gpio_out = gpio_base + GPIO_OUT_OFFSET;
        cfg.registers.gpio_in = gpio_base + GPIO_IN_OFFSET;
        cfg.registers.gpio_drive = gpio_base + GPIO_DRIVE_OFFSET;
        cfg.registers.gpio_mode = gpio_base + GPIO_MODE_OFFSET;
    }

    if let Some(i2c_base) = crate::yaml_get_u64(&["mmio", "i2c", "base"]) {
        cfg.registers.i2c_base = i2c_base + I2C_BASE_OFFSET;
    }

    if let Some(uart_base) = crate::yaml_get_u64(&["mmio", "uart", "base"]) {
        cfg.registers.uart_base = uart_base + UART_BASE_OFFSET;
    }

    if let Some(pci_base) = crate::yaml_get_u64(&["mmio", "pci", "base"]) {
        cfg.registers.pci_base = pci_base;
        cfg.registers.pci_cfg_addr = pci_base + PCI_CFG_ADDR_OFFSET;
        cfg.registers.pci_cfg_data = pci_base + PCI_CFG_DATA_OFFSET;
        cfg.registers.pci_status = pci_base + PCI_STATUS_OFFSET;
        cfg.registers.pci_ctrl = pci_base + PCI_CTRL_OFFSET;
    }

    if let Some(usb_base) = crate::yaml_get_u64(&["mmio", "usb", "base"]) {
        cfg.registers.usb_base = usb_base;
        cfg.registers.usb_ctrl = usb_base + USB_CTRL_OFFSET;
        cfg.registers.usb_status = usb_base + USB_STATUS_OFFSET;
        cfg.registers.usb_speed = usb_base + USB_SPEED_OFFSET;
        cfg.registers.usb_power = usb_base + USB_POWER_OFFSET;
    }

    if let Some(spi_base) = crate::yaml_get_u64(&["mmio", "spi", "base"]) {
        cfg.registers.spi_base = spi_base;
        cfg.registers.spi_ctrl = spi_base + SPI_CTRL_OFFSET;
        cfg.registers.spi_status = spi_base + SPI_STATUS_OFFSET;
        cfg.registers.spi_tx = spi_base + SPI_TX_OFFSET;
        cfg.registers.spi_rx = spi_base + SPI_RX_OFFSET;
        cfg.registers.spi_clk = spi_base + SPI_CLK_OFFSET;
    }

    if let Some(refresh_ctrl) = crate::yaml_get_u64(&["mmio", "memory", "refresh_ctrl"]) {
        cfg.registers.refresh_ctrl = refresh_ctrl;
        cfg.registers.memc_refresh_reg = refresh_ctrl;
    }

    if let Some(timing_reg) = crate::yaml_get_u64(&["mmio", "memory", "timing_reg"]) {
        cfg.registers.ram_timing_ctrl = timing_reg;
        cfg.registers.memc_timing_reg = timing_reg;
    }

    let mut brightness_base_set = false;
    if let Some(brightness_base) = crate::yaml_get_u64(&["mmio", "display", "brightness_base"]) {
        cfg.registers.brightness_base = brightness_base;
        cfg.registers.brightness_ctrl = brightness_base + BRIGHTNESS_CTRL_OFFSET;
        cfg.registers.brightness_status = brightness_base + BRIGHTNESS_STATUS_OFFSET;
        cfg.registers.brightness_level = brightness_base + BRIGHTNESS_LEVEL_OFFSET;
        cfg.registers.brightness_min = brightness_base + BRIGHTNESS_MIN_OFFSET;
        cfg.registers.brightness_max = brightness_base + BRIGHTNESS_MAX_OFFSET;
        cfg.registers.brightness_config = brightness_base + BRIGHTNESS_CONFIG_OFFSET;
        cfg.registers.brightness_mode = brightness_base + BRIGHTNESS_MODE_OFFSET;
        cfg.registers.brightness_data = brightness_base + BRIGHTNESS_DATA_OFFSET;
        brightness_base_set = true;
    }

    if let Some(mdp_base) = crate::yaml_get_u64(&["mmio", "display", "mdp_base"]) {
        cfg.registers.display_ctrl_base = mdp_base;
        cfg.registers.display_ctrl = mdp_base + DISPLAY_CTRL_OFFSET;
        cfg.registers.display_status = mdp_base + DISPLAY_STATUS_OFFSET;
        cfg.registers.display_width = mdp_base + DISPLAY_WIDTH_OFFSET;
        cfg.registers.display_height = mdp_base + DISPLAY_HEIGHT_OFFSET;
        cfg.registers.display_mode = mdp_base + DISPLAY_MODE_OFFSET;
        cfg.registers.display_refresh = mdp_base + DISPLAY_REFRESH_OFFSET;
        cfg.registers.display_config = mdp_base + DISPLAY_CONFIG_OFFSET;
        cfg.registers.display_data = mdp_base + DISPLAY_DATA_OFFSET;

        if !brightness_base_set {
            let brightness_base = mdp_base + 0x1000;
            cfg.registers.brightness_base = brightness_base;
            cfg.registers.brightness_ctrl = brightness_base + BRIGHTNESS_CTRL_OFFSET;
            cfg.registers.brightness_status = brightness_base + BRIGHTNESS_STATUS_OFFSET;
            cfg.registers.brightness_level = brightness_base + BRIGHTNESS_LEVEL_OFFSET;
            cfg.registers.brightness_min = brightness_base + BRIGHTNESS_MIN_OFFSET;
            cfg.registers.brightness_max = brightness_base + BRIGHTNESS_MAX_OFFSET;
            cfg.registers.brightness_config = brightness_base + BRIGHTNESS_CONFIG_OFFSET;
            cfg.registers.brightness_mode = brightness_base + BRIGHTNESS_MODE_OFFSET;
            cfg.registers.brightness_data = brightness_base + BRIGHTNESS_DATA_OFFSET;
        }
    }

    if let Some(screen_base) = crate::yaml_get_u64(&["mmio", "display", "screen_base"]) {
        cfg.registers.screen_base = screen_base;
        cfg.registers.screen_ctrl = screen_base + SCREEN_CTRL_OFFSET;
        cfg.registers.screen_status = screen_base + SCREEN_STATUS_OFFSET;
        cfg.registers.screen_width = screen_base + SCREEN_WIDTH_OFFSET;
        cfg.registers.screen_height = screen_base + SCREEN_HEIGHT_OFFSET;
        cfg.registers.screen_refresh = screen_base + SCREEN_REFRESH_OFFSET;
        cfg.registers.screen_brightness = screen_base + SCREEN_BRIGHTNESS_OFFSET;
        cfg.registers.screen_config = screen_base + SCREEN_CONFIG_OFFSET;
        cfg.registers.screen_data = screen_base + SCREEN_DATA_OFFSET;
    } else if let Some(dsi0_base) = crate::yaml_get_u64(&["mmio", "display", "dsi_0"]) {
        cfg.registers.screen_base = dsi0_base;
        cfg.registers.screen_ctrl = dsi0_base + SCREEN_CTRL_OFFSET;
        cfg.registers.screen_status = dsi0_base + SCREEN_STATUS_OFFSET;
        cfg.registers.screen_width = dsi0_base + SCREEN_WIDTH_OFFSET;
        cfg.registers.screen_height = dsi0_base + SCREEN_HEIGHT_OFFSET;
        cfg.registers.screen_refresh = dsi0_base + SCREEN_REFRESH_OFFSET;
        cfg.registers.screen_brightness = dsi0_base + SCREEN_BRIGHTNESS_OFFSET;
        cfg.registers.screen_config = dsi0_base + SCREEN_CONFIG_OFFSET;
        cfg.registers.screen_data = dsi0_base + SCREEN_DATA_OFFSET;
    }

    if let Some(isp_base) = crate::yaml_get_u64(&["mmio", "camera", "isp_base"]) {
        cfg.registers.front_isp_base = isp_base;
        cfg.registers.front_isp_ctrl = isp_base + ISP_CTRL_OFFSET;
        cfg.registers.front_isp_status = isp_base + ISP_STATUS_OFFSET;
        cfg.registers.front_isp_config = isp_base + ISP_CONFIG_OFFSET;
        cfg.registers.front_isp_resolution = isp_base + ISP_RESOLUTION_OFFSET;
        cfg.registers.front_isp_frame_rate = isp_base + ISP_FRAME_RATE_OFFSET;
        cfg.registers.front_isp_mode = isp_base + ISP_MODE_OFFSET;
        cfg.registers.front_isp_format = isp_base + ISP_FORMAT_OFFSET;
        cfg.registers.front_isp_data = isp_base + ISP_DATA_OFFSET;

        cfg.registers.rear_isp_base = isp_base;
        cfg.registers.rear_isp_ctrl = isp_base + ISP_CTRL_OFFSET;
        cfg.registers.rear_isp_status = isp_base + ISP_STATUS_OFFSET;
        cfg.registers.rear_isp_config = isp_base + ISP_CONFIG_OFFSET;
        cfg.registers.rear_isp_resolution = isp_base + ISP_RESOLUTION_OFFSET;
        cfg.registers.rear_isp_frame_rate = isp_base + ISP_FRAME_RATE_OFFSET;
        cfg.registers.rear_isp_mode = isp_base + ISP_MODE_OFFSET;
        cfg.registers.rear_isp_format = isp_base + ISP_FORMAT_OFFSET;
        cfg.registers.rear_isp_data = isp_base + ISP_DATA_OFFSET;
    }

    if let Some(seninf_base) = crate::yaml_get_u64(&["mmio", "camera", "seninf_base"]) {
        cfg.registers.camera_ctrl_base = seninf_base;
        cfg.registers.camera_ctrl = seninf_base + CAMERA_CTRL_OFFSET;
        cfg.registers.camera_status = seninf_base + CAMERA_STATUS_OFFSET;
        cfg.registers.camera_select = seninf_base + CAMERA_SELECT_OFFSET;
        cfg.registers.camera_power = seninf_base + CAMERA_POWER_OFFSET;
        cfg.registers.camera_reset = seninf_base + CAMERA_RESET_OFFSET;
        cfg.registers.camera_config = seninf_base + CAMERA_CONFIG_OFFSET;
        cfg.registers.camera_mode = seninf_base + CAMERA_MODE_OFFSET;
        cfg.registers.camera_data = seninf_base + CAMERA_DATA_OFFSET;
    }

    if let Some(lte_phy) = crate::yaml_get_u64(&["mmio", "modem", "lte_phy"]) {
        cfg.registers.lte_base = lte_phy;
    }
    if let Some(nr_phy) = crate::yaml_get_u64(&["mmio", "modem", "nr_phy"]) {
        cfg.registers.fiveg_base = nr_phy;
    }
    if let Some(gsm_phy) = crate::yaml_get_u64(&["mmio", "modem", "gsm_phy"]) {
        cfg.registers.gsm_base = gsm_phy;
    }

    if let Some(nfc_base) = crate::yaml_get_u64(&["mmio", "nfc", "base"])
        .or_else(|| crate::yaml_get_u64(&["mmio", "nfc", "nfc_base"]))
    {
        cfg.registers.nfc_base = nfc_base;
        cfg.registers.nfc_ctrl_reg = nfc_base + NFC_CTRL_OFFSET;
        cfg.registers.nfc_status_reg = nfc_base + NFC_STATUS_OFFSET;
        cfg.registers.nfc_interrupt_reg = nfc_base + NFC_INTERRUPT_OFFSET;
        cfg.registers.nfc_error_reg = nfc_base + NFC_ERROR_OFFSET;
        cfg.registers.nfc_command_reg = nfc_base + NFC_COMMAND_OFFSET;
        cfg.registers.nfc_response_reg = nfc_base + NFC_RESPONSE_OFFSET;
        cfg.registers.nfc_fifo_reg = nfc_base + NFC_FIFO_OFFSET;
        cfg.registers.nfc_timeout_reg = nfc_base + NFC_TIMEOUT_OFFSET;
        cfg.registers.nfc_config_reg = nfc_base + NFC_CONFIG_OFFSET;
        cfg.registers.nfc_mode_reg = nfc_base + NFC_MODE_OFFSET;

        cfg.registers.reader_config_reg = nfc_base + READER_CONFIG_OFFSET;
        cfg.registers.reader_detect_reg = nfc_base + READER_DETECT_OFFSET;
        cfg.registers.uid_reg = nfc_base + UID_OFFSET;
        cfg.registers.whitelist_reg = nfc_base + WHITELIST_OFFSET;

        cfg.registers.writer_config_reg = nfc_base + WRITER_CONFIG_OFFSET;
        cfg.registers.writer_erase_reg = nfc_base + WRITER_ERASE_OFFSET;
        cfg.registers.write_data_reg = nfc_base + WRITE_DATA_OFFSET;
        cfg.registers.write_addr_reg = nfc_base + WRITE_ADDR_OFFSET;

        cfg.registers.payment_ctrl_reg = nfc_base + PAYMENT_CTRL_OFFSET;
        cfg.registers.payment_status_reg = nfc_base + PAYMENT_STATUS_OFFSET;
        cfg.registers.payment_amount_reg = nfc_base + PAYMENT_AMOUNT_OFFSET;
        cfg.registers.payment_currency_reg = nfc_base + PAYMENT_CURRENCY_OFFSET;
        cfg.registers.payment_security_reg = nfc_base + PAYMENT_SECURITY_OFFSET;
        cfg.registers.payment_log_reg = nfc_base + PAYMENT_LOG_OFFSET;
        cfg.registers.payment_config_reg = nfc_base + PAYMENT_CONFIG_OFFSET;
    }

    let mut audio_codec_set = false;
    let mut speaker_set = false;
    let mut mic_set = false;
    let mut jack_set = false;
    let mut anc_set = false;
    let mut input_set = false;

    if let Some(codec_base) = crate::yaml_get_u64(&["mmio", "audio", "codec_base"]) {
        cfg.registers.audio_codec_base = codec_base;
        audio_codec_set = true;
    }

    if let Some(dac_base) = crate::yaml_get_u64(&["mmio", "audio", "dac"]) {
        cfg.registers.speaker_base = dac_base;
        speaker_set = true;
    }

    if let Some(adc_base) = crate::yaml_get_u64(&["mmio", "audio", "adc"]) {
        cfg.registers.microphone_base = adc_base;
        mic_set = true;
    }

    if let Some(jack_base) = crate::yaml_get_u64(&["mmio", "audio", "jack_base"]) {
        cfg.registers.headphone_jack_base = jack_base;
        jack_set = true;
    }

    if let Some(anc_base) = crate::yaml_get_u64(&["mmio", "audio", "anc_base"]) {
        cfg.registers.noise_cancellation_base = anc_base;
        anc_set = true;
    }

    if let Some(input_base) = crate::yaml_get_u64(&["mmio", "audio", "input_base"]) {
        cfg.registers.audio_input_base = input_base;
        input_set = true;
    }

    if let Some(aud_base) = crate::yaml_get_u64(&["mmio", "audio", "aud_base"]) {
        cfg.registers.audio_base = aud_base;

        if !audio_codec_set {
            cfg.registers.audio_codec_base = aud_base + AUDIO_CODEC_OFFSET;
        }
        if !speaker_set {
            cfg.registers.speaker_base = aud_base + AUDIO_SPEAKER_OFFSET;
        }
        if !mic_set {
            cfg.registers.microphone_base = aud_base + AUDIO_MIC_OFFSET;
        }
        if !jack_set {
            cfg.registers.headphone_jack_base = aud_base + AUDIO_JACK_OFFSET;
        }
        if !anc_set {
            cfg.registers.noise_cancellation_base = aud_base + AUDIO_ANC_OFFSET;
        }
        if !input_set {
            cfg.registers.audio_input_base = aud_base + AUDIO_INPUT_OFFSET;
        }
    }

    if let Some(bt_base) = crate::yaml_get_u64(&["mmio", "modem", "bt_base"]) {
        cfg.registers.bt_base = bt_base;
        cfg.registers.bt_ctrl = bt_base + BT_CTRL_OFFSET;
        cfg.registers.bt_status = bt_base + BT_STATUS_OFFSET;
        cfg.registers.bt_freq = bt_base + BT_FREQ_OFFSET;
        cfg.registers.bt_band = bt_base + BT_BAND_OFFSET;
    }

    if let Some(wifi_base) = crate::yaml_get_u64(&["mmio", "modem", "wifi_base"]) {
        cfg.registers.wifi_base = wifi_base;
        cfg.registers.wifi_ctrl = wifi_base + WIFI_CTRL_OFFSET;
        cfg.registers.wifi_status = wifi_base + WIFI_STATUS_OFFSET;
        cfg.registers.wifi_freq = wifi_base + WIFI_FREQ_OFFSET;
        cfg.registers.wifi_channel = wifi_base + WIFI_CHANNEL_OFFSET;
    }

    if let Some(esim_base) = crate::yaml_get_u64(&["mmio", "modem", "esim_base"]) {
        cfg.registers.esim_base = esim_base;
    }

    if let Some(sim_base) = crate::yaml_get_u64(&["mmio", "modem", "sim_base"]) {
        cfg.registers.sim_base = sim_base;
    }

    if let Some(satellite_base) = crate::yaml_get_u64(&["mmio", "modem", "satellite_base"]) {
        cfg.registers.satellite_base = satellite_base;
    }

    if let Some(zigbee_base) = crate::yaml_get_u64(&["mmio", "modem", "zigbee_base"]) {
        cfg.registers.zigbee_base = zigbee_base;
    }

    if let Some(thread_base) = crate::yaml_get_u64(&["mmio", "modem", "thread_base"]) {
        cfg.registers.thread_base = thread_base;
    }

    if let Some(power_base) = crate::yaml_get_u64(&["mmio", "power", "power_base"]) {
        cfg.registers.power_base = power_base;
    }
    if let Some(vdd_core) = crate::yaml_get_u64(&["mmio", "power", "vdd_core"]) {
        cfg.registers.vdd_core = vdd_core;
    }
    if let Some(vdd_gpu) = crate::yaml_get_u64(&["mmio", "power", "vdd_gpu"]) {
        cfg.registers.vdd_gpu = vdd_gpu;
    }
    if let Some(vdd_modem) = crate::yaml_get_u64(&["mmio", "power", "vdd_modem"]) {
        cfg.registers.vdd_modem = vdd_modem;
    }
    if let Some(vdd_io) = crate::yaml_get_u64(&["mmio", "power", "vdd_io"]) {
        cfg.registers.vdd_io = vdd_io;
    }

    if let Some(addr) = crate::yaml_get_u64(&["mmio", "pmic", "slave_address"]) {
        cfg.registers.battery_i2c_addr = addr as u8;
    }

    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "charging", "reg_control"]) {
        cfg.registers.pmic_chg_ctrl = reg as u8;
    }
    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "charging", "reg_status"]) {
        cfg.registers.pmic_chg_status = reg as u8;
    }
    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "charging", "reg_current"]) {
        cfg.registers.pmic_chg_current = reg as u8;
        cfg.registers.battery_reg_current = reg as u8;
    }
    let mut chg_voltage_set = false;
    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "charging", "reg_voltage"]) {
        cfg.registers.pmic_chg_voltage = reg as u8;
        chg_voltage_set = true;
    }
    if !chg_voltage_set && cfg.registers.pmic_chg_current == cfg.registers.pmic_chg_voltage {
        cfg.registers.pmic_chg_voltage = cfg.registers.pmic_chg_current.saturating_add(1);
    }

    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "battery", "reg_voltage"]) {
        cfg.registers.battery_reg_voltage = reg as u8;
    }
    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "battery", "reg_capacity"]) {
        cfg.registers.battery_reg_soc = reg as u8;
    }
    if let Some(reg) = crate::yaml_get_u64(&["mmio", "pmic", "battery", "reg_temp"]) {
        cfg.registers.battery_reg_status = reg as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HardwareConfig::default_redmi_15c();
        assert_eq!(config.cpu.cores, 8);
        assert_eq!(config.ram.size_mb, 12288);
        assert_eq!(config.security.level, 5);
    }

    #[test]
    fn test_cpu_config() {
        let config = HardwareConfig::default_redmi_15c();
        assert!(config.cpu.max_frequency > config.cpu.min_frequency);
        assert_eq!(config.cpu.max_frequency, 3000);
    }

    #[test]
    fn test_thermal_config() {
        let config = HardwareConfig::default_redmi_15c();
        assert!(config.thermal.critical_temp > config.thermal.throttle_temp);
        assert!(config.thermal.throttle_temp > config.thermal.warning_temp);
    }
}
