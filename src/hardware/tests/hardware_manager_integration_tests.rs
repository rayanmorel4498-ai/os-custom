use libc::{mmap, munmap, MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use redmi_hardware::{config, HardwareManager, SystemHealth};
use std::ptr;

const MMIO_SIZE: usize = 1024 * 1024;

fn map_mmio() -> (*mut u8, usize) {
    unsafe {
        let ptr = mmap(
            ptr::null_mut(),
            MMIO_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        if ptr == MAP_FAILED {
            panic!("mmap failed");
        }
        let base = ptr as *mut u32;
        let len = MMIO_SIZE / 4;
        let slice = core::slice::from_raw_parts_mut(base, len);
        for v in slice.iter_mut() {
            *v = 0xFFFF_FFFF;
        }
        (ptr as *mut u8, MMIO_SIZE)
    }
}

fn unmap_mmio(ptr: *mut u8, size: usize) {
    unsafe {
        munmap(ptr as *mut _, size);
    }
}

fn mmio_write(addr: u64, value: u32) {
    unsafe {
        (addr as *mut u32).write_volatile(value);
    }
}

fn build_secure_yaml(base: u64) -> String {
    let memc_base = base + 0x70000;
    let phy_base = base + 0x71000;
    let gpio_base = base + 0x72000;
    let i2c_base = base + 0x73000;
    let uart_base = base + 0x74000;
    let pci_base = base + 0x75000;
    let usb_base = base + 0x76000;
    let spi_base = base + 0x77000;
    let display_base = base + 0x60000;
    let display_brightness = base + 0x61000;
    let camera_base = base + 0x50000;
    let modem_base = base + 0x30000;
    let nfc_base = base + 0x40000;
    let audio_codec = base + 0x20000;
    let audio_dac = base + 0x21000;
    let audio_adc = base + 0x22000;
    let audio_jack = base + 0x23000;
    let audio_anc = base + 0x24000;
    let audio_input = base + 0x25000;
    let audio_aud = base + 0x26000;
    let power_base = base + 0x10000;

    format!(
        "mmio:\n  memory:\n    ddr_phy_base: 0x{phy_base:X}\n    memc_base: 0x{memc_base:X}\n  gpio:\n    base: 0x{gpio_base:X}\n  i2c:\n    base: 0x{i2c_base:X}\n  uart:\n    base: 0x{uart_base:X}\n  pci:\n    base: 0x{pci_base:X}\n  usb:\n    base: 0x{usb_base:X}\n  spi:\n    base: 0x{spi_base:X}\n  display:\n    brightness_base: 0x{display_brightness:X}\n    mdp_base: 0x{display_base:X}\n    screen_base: 0x{display_base:X}\n  camera:\n    isp_base: 0x{camera_base:X}\n    seninf_base: 0x{camera_base:X}\n  modem:\n    lte_phy: 0x{modem_base:X}\n    nr_phy: 0x{modem_base:X}\n    gsm_phy: 0x{modem_base:X}\n    bt_base: 0x{modem_base:X}\n    wifi_base: 0x{modem_base:X}\n    esim_base: 0x{modem_base:X}\n    sim_base: 0x{modem_base:X}\n    satellite_base: 0x{modem_base:X}\n    zigbee_base: 0x{modem_base:X}\n    thread_base: 0x{modem_base:X}\n  nfc:\n    base: 0x{nfc_base:X}\n  audio:\n    codec_base: 0x{audio_codec:X}\n    dac: 0x{audio_dac:X}\n    adc: 0x{audio_adc:X}\n    jack_base: 0x{audio_jack:X}\n    anc_base: 0x{audio_anc:X}\n    input_base: 0x{audio_input:X}\n    aud_base: 0x{audio_aud:X}\n  power:\n    power_base: 0x{power_base:X}\n    vdd_core: 0x{power_base:X}\n    vdd_gpu: 0x{power_base:X}\n    vdd_modem: 0x{power_base:X}\n    vdd_io: 0x{power_base:X}\n  pmic:\n    slave_address: 0x2D\n    charging:\n      reg_control: 0x{power_base:X}\n      reg_status: 0x{power_base:X}\n      reg_current: 0x{power_base:X}\n      reg_voltage: 0x{power_base:X}\n    battery:\n      reg_voltage: 0x{power_base:X}\n      reg_capacity: 0x{power_base:X}\n      reg_temp: 0x{power_base:X}\n"
    )
}

fn apply_test_config(base: u64, ram_size_mb: u32) {
    let yaml = build_secure_yaml(base);
    let leaked = Box::leak(yaml.into_boxed_str());
    redmi_hardware::set_secure_yaml(leaked);
    config::init_config();

    let mut cfg = config::get_config();
    cfg.ram.frequency = 1800;
    cfg.ram.size_mb = ram_size_mb;

    cfg.registers.cpu_core_ctrl_base = base + 0x0000;
    cfg.registers.cpu_big_freq_reg = base + 0x0100;
    cfg.registers.cpu_little_freq_reg = base + 0x0104;
    cfg.registers.cpu_big_volt_reg = base + 0x0108;
    cfg.registers.cpu_little_volt_reg = base + 0x010C;

    cfg.registers.gpu_power_control = base + 0x0200;
    cfg.registers.gpu_clock_control = base + 0x0204;
    cfg.registers.gpu_reset_control = base + 0x0208;
    cfg.registers.gpu_shader_cores_enable = base + 0x020C;
    cfg.registers.gpu_power_domain_0 = base + 0x0210;
    cfg.registers.gpu_power_domain_1 = base + 0x0214;
    cfg.registers.gpu_power_domain_2 = base + 0x0218;
    cfg.registers.gpu_power_domain_3 = base + 0x021C;
    cfg.registers.gpu_command_reg = base + 0x0220;

    cfg.registers.ram_base = base + 0x0300;

    cfg.registers.gnss_ctrl_base = base + 0x0400;
    cfg.registers.gnss_ctrl = base + 0x0400;
    cfg.registers.gnss_status = base + 0x0404;
    cfg.registers.gnss_lat = base + 0x0408;
    cfg.registers.gnss_lon = base + 0x040C;
    cfg.registers.gnss_alt = base + 0x0410;
    cfg.registers.gnss_config = base + 0x0414;
    cfg.registers.gnss_mode = base + 0x0418;
    cfg.registers.gnss_data = base + 0x041C;

    cfg.registers.fingerprint_base = base + 0x0500;
    cfg.registers.iris_base = base + 0x0600;
    cfg.registers.voice_base = base + 0x0700;
    cfg.registers.faceid_base = base + 0x0800;

    unsafe { config::set_config(cfg) };
}

#[test]
fn init_all_ready() {
    let (ptr, size) = map_mmio();
    let base = ptr as u64;
    apply_test_config(base, 1);

    let mut manager = HardwareManager::new();
    let result = manager.init_all();

    assert!(result.is_ok());
    assert_eq!(manager.system_health(), SystemHealth::Ready);
    assert!(manager.errors().is_empty());

    unmap_mmio(ptr, size);
}

#[test]
fn init_all_degraded_when_audio_fails() {
    let (ptr, size) = map_mmio();
    let base = ptr as u64;
    apply_test_config(base, 1);

    let audio_codec_status = (base + 0x20000 + 0x0004) as u64;
    let audio_dac_status = (base + 0x21000 + 0x0004) as u64;
    let audio_adc_status = (base + 0x22000 + 0x0004) as u64;
    let audio_jack_status = (base + 0x23000 + 0x0004) as u64;
    let audio_anc_status = (base + 0x24000 + 0x0004) as u64;
    let audio_input_status = (base + 0x25000 + 0x0004) as u64;

    mmio_write(audio_codec_status, 0);
    mmio_write(audio_dac_status, 0);
    mmio_write(audio_adc_status, 0);
    mmio_write(audio_jack_status, 0);
    mmio_write(audio_anc_status, 0);
    mmio_write(audio_input_status, 0);

    let mut manager = HardwareManager::new();
    let result = manager.init_all();

    assert!(result.is_ok());
    assert_eq!(manager.system_health(), SystemHealth::DegradedPartial);
    assert!(!manager.errors().is_empty());

    unmap_mmio(ptr, size);
}

#[test]
fn low_power_and_reset_transitions() {
    let (ptr, size) = map_mmio();
    let base = ptr as u64;
    apply_test_config(base, 1);

    let mut manager = HardwareManager::new();
    let _ = manager.init_all();

    manager.low_power_mode();
    assert_eq!(manager.gpu_state, redmi_hardware::ComponentState::Sleeping);

    manager.hard_reset();
    assert_eq!(manager.cpu_state, redmi_hardware::ComponentState::Uninitialized);
    assert_eq!(manager.gpu_state, redmi_hardware::ComponentState::Uninitialized);
    assert_eq!(manager.ram_state, redmi_hardware::ComponentState::Uninitialized);
    assert_eq!(manager.display_state, redmi_hardware::ComponentState::Uninitialized);

    unmap_mmio(ptr, size);
}
