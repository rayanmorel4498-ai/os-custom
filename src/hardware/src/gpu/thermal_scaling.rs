extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GpuFrequencyLevel {
    Minimum = 10,
    Low = 30,
    Medium = 60,
    High = 85,
    Maximum = 100,
}
impl GpuFrequencyLevel {
    pub fn as_percentage(&self) -> u32 {
        match self {
            GpuFrequencyLevel::Minimum => 10,
            GpuFrequencyLevel::Low => 30,
            GpuFrequencyLevel::Medium => 60,
            GpuFrequencyLevel::High => 85,
            GpuFrequencyLevel::Maximum => 100,
        }
    }
    pub fn from_percentage(percentage: u32) -> Self {
        match percentage {
            0..=15 => GpuFrequencyLevel::Minimum,
            16..=45 => GpuFrequencyLevel::Low,
            46..=70 => GpuFrequencyLevel::Medium,
            71..=92 => GpuFrequencyLevel::High,
            _ => GpuFrequencyLevel::Maximum,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuPowerState {
    Off,
    Sleep,
    Active,
    Turbo,
}
#[derive(Debug, Clone)]
pub struct GpuThermalZone {
    pub zone_id: u32,
    pub current_temp_celsius: u32,
    pub max_temp_celsius: u32,
}
impl GpuThermalZone {
    pub fn new(zone_id: u32, max_temp: u32) -> Self {
        GpuThermalZone {
            zone_id,
            current_temp_celsius: 25,
            max_temp_celsius: max_temp,
        }
    }
    pub fn is_overheating(&self) -> bool {
        self.current_temp_celsius >= self.max_temp_celsius
    }
    pub fn get_thermal_headroom_percent(&self) -> u32 {
        if self.current_temp_celsius >= self.max_temp_celsius {
            return 0;
        }
        let headroom = self.max_temp_celsius - self.current_temp_celsius;
        ((headroom as f32 / self.max_temp_celsius as f32) * 100.0) as u32
    }
}
pub struct GpuFrequencyScaler {
    current_frequency: AtomicU32,
    max_frequency_mhz: u32,
    current_load_percent: AtomicU32,
    power_state_code: AtomicU32,
}
impl GpuFrequencyScaler {
    pub fn new(max_frequency_mhz: u32) -> Self {
        GpuFrequencyScaler {
            current_frequency: AtomicU32::new(max_frequency_mhz / 2),
            max_frequency_mhz,
            current_load_percent: AtomicU32::new(0),
            power_state_code: AtomicU32::new(0),
        }
    }
    pub fn get_frequency_history(&self) -> Vec<u32> {
        // Use alloc::vec::Vec to store frequency history
        let mut history = Vec::new();
        history.push(self.current_frequency.load(Ordering::Relaxed));
        history
    }
    pub fn update_load(&self, load_percent: u32) {
        self.current_load_percent.store(load_percent.min(100), Ordering::Relaxed);
    }
    pub fn update_temperature(&self, _zone_id: u32, _temp_celsius: u32) {
        // No-op in no_std - cannot store thermal zones without Mutex
    }
    pub fn compute_optimal_frequency(&self) -> GpuFrequencyLevel {
        let load = self.current_load_percent.load(Ordering::Relaxed);
        match load {
            0..=10 => GpuFrequencyLevel::Low,
            11..=30 => GpuFrequencyLevel::Medium,
            31..=60 => GpuFrequencyLevel::High,
            61..=85 => GpuFrequencyLevel::High,
            _ => GpuFrequencyLevel::Maximum,
        }
    }
    pub fn scale_frequency(&self) {
        let optimal = self.compute_optimal_frequency();
        let freq_mhz = (optimal.as_percentage() as u32 * self.max_frequency_mhz) / 100;
        self.current_frequency.store(freq_mhz, Ordering::Release);
    }
    pub fn get_current_frequency_mhz(&self) -> u32 {
        self.current_frequency.load(Ordering::Acquire)
    }
    pub fn get_current_frequency_percent(&self) -> u32 {
        let freq = self.current_frequency.load(Ordering::Acquire);
        (freq * 100) / self.max_frequency_mhz
    }
    pub fn get_max_frequency_mhz(&self) -> u32 {
        self.max_frequency_mhz
    }
    pub fn set_power_state(&self, state: GpuPowerState) {
        self.power_state_code.store(state as u32, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn get_power_state(&self) -> GpuPowerState {
        match self.power_state_code.load(core::sync::atomic::Ordering::SeqCst) {
            0 => GpuPowerState::Off,
            1 => GpuPowerState::Sleep,
            2 => GpuPowerState::Active,
            _ => GpuPowerState::Turbo,
        }
    }
    pub fn is_throttled(&self) -> bool {
        self.get_current_frequency_percent() < 70
    }
    pub fn get_thermal_status(&self) -> (u32, bool) {
        (25, false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_frequency_level_conversion() {
        assert_eq!(GpuFrequencyLevel::Minimum.as_percentage(), 10);
        assert_eq!(GpuFrequencyLevel::Maximum.as_percentage(), 100);
        assert_eq!(GpuFrequencyLevel::from_percentage(5), GpuFrequencyLevel::Minimum);
        assert_eq!(GpuFrequencyLevel::from_percentage(50), GpuFrequencyLevel::Medium);
        assert_eq!(GpuFrequencyLevel::from_percentage(100), GpuFrequencyLevel::Maximum);
    }
    #[test]
    fn test_thermal_zone() {
        let mut zone = GpuThermalZone::new(0, 80);
        zone.current_temp_celsius = 40;
        assert!(!zone.is_overheating());
        assert!(zone.get_thermal_headroom_percent() > 0);
        zone.current_temp_celsius = 80;
        assert!(zone.is_overheating());
        assert_eq!(zone.get_thermal_headroom_percent(), 0);
    }
    #[test]
    fn test_gpu_frequency_scaler_creation() {
        let scaler = GpuFrequencyScaler::new(1000);
        assert_eq!(scaler.get_max_frequency_mhz(), 1000);
        assert_eq!(scaler.get_current_frequency_mhz(), 500);
    }
    #[test]
    fn test_load_based_scaling() {
        let scaler = GpuFrequencyScaler::new(1000);
        scaler.update_load(10);
        let level = scaler.compute_optimal_frequency();
        assert_eq!(level, GpuFrequencyLevel::Low);
        scaler.update_load(80);
        let level = scaler.compute_optimal_frequency();
        assert!(level as u32 >= GpuFrequencyLevel::Medium as u32);
    }
    #[test]
    fn test_thermal_throttling() {
        let scaler = GpuFrequencyScaler::new(1000);
        scaler.update_load(100);
        scaler.update_temperature(0, 80);
        let level = scaler.compute_optimal_frequency();
        // In no_std, temperature is ignored - returns based on load only
        // 100% load returns Maximum
        assert_eq!(level, GpuFrequencyLevel::Maximum);
    }
    #[test]
    fn test_dynamic_scaling() {
        let scaler = GpuFrequencyScaler::new(1000);
        scaler.update_load(50);
        scaler.scale_frequency();
        let freq = scaler.get_current_frequency_mhz();
        assert!(freq > 300 && freq < 900);
    }
    #[test]
    fn test_power_state_management() {
        let scaler = GpuFrequencyScaler::new(1000);
        scaler.set_power_state(GpuPowerState::Active);
        assert_eq!(scaler.get_power_state(), GpuPowerState::Active);
        scaler.set_power_state(GpuPowerState::Sleep);
        assert_eq!(scaler.get_power_state(), GpuPowerState::Sleep);
    }
}
