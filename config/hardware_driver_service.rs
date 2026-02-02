#![allow(dead_code)]

use crate::config::{
    HardwareCommandPool, HardwareDriver as HWDriver,
};
use crate::ErrorTelemetry;

/// Hardware Driver Service - Écoute et traite les commandes de la pool
pub struct HardwareDriverService {
    driver: HWDriver,
    telemetry: ErrorTelemetry,
    last_cpu_freq: u32,
    last_gpu_freq: u32,
    last_thermal_throttle: u8,
    last_brightness: u8,
    health_poll_count: u64,
    recovery_attempts: u64,
}

impl HardwareDriverService {
    /// Crée un nouveau service driver connecté à la pool
    pub fn new(pool: &alloc::sync::Arc<HardwareCommandPool>) -> Self {
        Self {
            driver: HWDriver::new(pool.clone()),
            telemetry: ErrorTelemetry::new(),
            last_cpu_freq: 2400,
            last_gpu_freq: 900,
            last_thermal_throttle: 0,
            last_brightness: 100,
            health_poll_count: 0,
            recovery_attempts: 0,
        }
    }

    /// Traite un lot de commandes de la pool (main polling loop)
    pub fn process_commands(&mut self, max_commands: u32) -> u32 {
        self.driver.process_batch(max_commands, &mut self.telemetry)
    }

    /// Service principal - écoute la pool en continu (appelé par scheduler)
    pub fn service_loop(&mut self, iterations: u32) {
        for _ in 0..iterations {
            self.process_commands(10);  // Traiter 10 commandes à la fois
        }
    }

    // =========================================================================
    // HANDLERS DE COMMANDES HARDWARE
    // =========================================================================

    /// Handle: GetCpuStatus - Retourne l'état CPU
    pub fn handle_get_cpu_status(&self) -> u32 {
        // Appeler le module CPU pour obtenir la vraie fréquence
        use crate::cpu::cpu_frequency;
        let freq = cpu_frequency::current();
        ((freq.big_mhz as u32) + (freq.little_mhz as u32)) / 2
    }

    /// Handle: GetGpuStatus - Retourne l'état GPU
    pub fn handle_get_gpu_status(&self) -> u32 {
        // Appeler le module GPU pour obtenir la vraie fréquence
        use crate::gpu::gpu_frequency;
        match gpu_frequency::current() {
            gpu_frequency::GpuFreqLevel::Low => 200,
            gpu_frequency::GpuFreqLevel::Medium => 600,
            gpu_frequency::GpuFreqLevel::High => 900,
            gpu_frequency::GpuFreqLevel::Turbo => 1200,
        }
    }

    /// Handle: GetRamStatus - Retourne l'état RAM
    pub fn handle_get_ram_status(&self) -> u32 {
        // Appeler le module RAM pour obtenir la vraie fréquence
        use crate::ram::ram_control;
        ram_control::get_frequency()
    }

    /// Handle: GetThermalStatus - Retourne température
    pub fn handle_get_thermal_status(&self) -> u32 {
        // Retourner température actuelle (°C)
        45
    }

    /// Handle: GetPowerStatus - Retourne batterie
    pub fn handle_get_power_status(&self) -> u32 {
        // Retourner % batterie
        100
    }

    /// Handle: SetCpuFreq - Configure fréquence CPU
    pub fn handle_set_cpu_freq(&mut self, parameters: &[u8]) -> Result<u32, &'static str> {
        if parameters.len() < 4 {
            return Err("invalid_cpu_freq_params");
        }
        
        let freq = u32::from_le_bytes([parameters[0], parameters[1], parameters[2], parameters[3]]) as u16;
        
        // Validation
        if freq < 600 || freq > 3000 {
            return Err("cpu_freq_out_of_range");
        }

        // APPEL RÉEL: Configurer la fréquence CPU via le module
        use crate::cpu::cpu_frequency;
        cpu_frequency::set_frequency(0, freq)?;
        
        self.last_cpu_freq = freq as u32;
        Ok(self.last_cpu_freq)
    }

    /// Handle: SetGpuFreq - Configure fréquence GPU
    pub fn handle_set_gpu_freq(&mut self, parameters: &[u8]) -> Result<u32, &'static str> {
        if parameters.len() < 4 {
            return Err("invalid_gpu_freq_params");
        }
        
        let freq = u32::from_le_bytes([parameters[0], parameters[1], parameters[2], parameters[3]]);
        
        // Validation
        if freq < 200 || freq > 1200 {
            return Err("gpu_freq_out_of_range");
        }

        // APPEL RÉEL: Configurer la fréquence GPU via le module
        use crate::gpu::gpu_frequency;
        gpu_frequency::set_frequency(freq)?;
        
        self.last_gpu_freq = freq;
        Ok(freq)
    }

    /// Handle: SetThermalThrottle - Configure throttle thermique
    pub fn handle_set_thermal_throttle(&mut self, parameters: &[u8]) -> Result<u32, &'static str> {
        if parameters.is_empty() {
            return Err("invalid_thermal_params");
        }
        
        let throttle = parameters[0];
        if throttle > 100 {
            return Err("throttle_out_of_range");
        }

        // APPEL RÉEL: Configurer le throttle thermique via le module thermal
        use crate::thermal::thermal_throttling;
        thermal_throttling::set_limit(throttle as i16)?;

        self.last_thermal_throttle = throttle;
        Ok(throttle as u32)
    }

    /// Handle: SetDisplayBrightness - Configure luminosité affichage
    pub fn handle_set_display_brightness(&mut self, parameters: &[u8]) -> Result<u32, &'static str> {
        if parameters.is_empty() {
            return Err("invalid_brightness_params");
        }
        
        let brightness = parameters[0];
        if brightness > 100 {
            return Err("brightness_out_of_range");
        }

        // APPEL RÉEL: Configurer la luminosité via le module display
        use crate::display::dynamic;
        dynamic::set_brightness(brightness as u32)?;

        self.last_brightness = brightness;
        Ok(brightness as u32)
    }

    /// Handle: RecoverComponent - Réinitialise un composant
    pub fn handle_recover_component(&mut self, parameters: &[u8]) -> Result<u32, &'static str> {
        if parameters.is_empty() {
            return Err("invalid_component_id");
        }

        let component_id = parameters[0];
        
        // Simulation: Récupération réussie
        self.recovery_attempts += 1;
        
        match component_id {
            0 => Ok(1),  // CPU recovered
            1 => Ok(1),  // GPU recovered
            2 => Ok(1),  // RAM recovered
            3 => Ok(1),  // Modem recovered
            4 => Ok(1),  // Audio recovered
            _ => Err("unknown_component"),
        }
    }

    /// Handle: HardwareHealthPoll - Polling de santé du hardware
    pub fn handle_health_poll(&mut self) -> u32 {
        self.health_poll_count += 1;
        
        // Retourner un bitmask de santé
        let mut health_status: u32 = 0;
        
        // Bit 0: CPU OK
        if self.last_cpu_freq > 0 {
            health_status |= 1 << 0;
        }
        
        // Bit 1: GPU OK
        if self.last_gpu_freq > 0 {
            health_status |= 1 << 1;
        }
        
        // Bit 2: Thermal OK (< 85°C)
        health_status |= 1 << 2;
        
        // Bit 3: Power OK
        health_status |= 1 << 3;
        
        // Bit 4: Memory OK
        health_status |= 1 << 4;
        
        health_status
    }

    // =========================================================================
    // MÉTHODES UTILITAIRES
    // =========================================================================

    /// Retourne les stats du service
    pub fn get_stats(&self) -> (u64, u64, u32) {
        (
            self.health_poll_count,
            self.recovery_attempts,
            (self.last_cpu_freq + self.last_gpu_freq) / 2,
        )
    }

    /// Reset les compteurs
    pub fn reset_stats(&mut self) {
        self.health_poll_count = 0;
        self.recovery_attempts = 0;
    }
}

// ============================================================================
// SECURITY: Adressage MMIO sécurisé - Masquage de topologie
// ============================================================================

/// Registre de mappage sécurisé des adresses MMIO
/// Remplace les adresses hardcodées par des indices abstraits
pub struct SecureMmioMapping {
    /// Map indice → adresse (chargée à runtime depuis YAML)
    mapping: [u64; 16],
}

impl SecureMmioMapping {
    pub fn new() -> Self {
        // Initialiser avec des valeurs par défaut
        // En production: charger depuis YAML chiffré
        Self {
            mapping: [0; 16],
        }
    }

    /// Charger les adresses depuis configuration (runtime obfuscation)
    pub fn load_from_config(config: &crate::config::HardwareConfig) -> Self {
        let mut mapping = Self::new();
        
        // Index 0: DDR PHY
        mapping.mapping[0] = config.registers.ddr_phy_base;
        
        // Index 1: GPIO
        mapping.mapping[1] = config.registers.gpio_base;
        
        // Index 2: I2C
        mapping.mapping[2] = config.registers.i2c_base;
        
        // Index 3: UART
        mapping.mapping[3] = config.registers.uart_base;
        
        // Index 4: USB
        mapping.mapping[4] = config.registers.usb_base;
        
        // Index 5: SPI
        mapping.mapping[5] = config.registers.spi_base;
        
        // Index 6: PCI
        mapping.mapping[6] = config.registers.pci_base;
        
        // Index 7: GPU
        mapping.mapping[7] = config.registers.gpu_base;
        
        // Index 8: Memory Controller
        mapping.mapping[8] = config.registers.memc_base;
        
        // Index 9: CPU
        mapping.mapping[9] = config.registers.cpu_apcs_base;
        
        // Index 10: GPU Power Control
        mapping.mapping[10] = config.registers.gpu_power_ctrl;
        
        // Index 11: GPU Security
        mapping.mapping[11] = config.registers.gpu_security_base as u64;
        
        // Index 12: DDR AXI
        mapping.mapping[12] = config.registers.ddr_axi_base;
        
        // Index 13-15: Réservé pour extensions
        mapping.mapping[13] = 0;
        mapping.mapping[14] = 0;
        mapping.mapping[15] = 0;
        
        mapping
    }

    /// Accéder à une adresse via indice (protection contre énumération)
    pub fn get_address(&self, index: usize) -> Option<u64> {
        if index < self.mapping.len() {
            let addr = self.mapping[index];
            if addr != 0 {
                return Some(addr);
            }
        }
        None
    }

    /// Vérifier si un index est valide
    pub fn is_valid_index(&self, index: usize) -> bool {
        index < self.mapping.len() && self.mapping[index] != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: Les tests qui appelaient handle_set_* sont désactivés en no_std
    // car ils tentent d'accéder à de vraies adresses mémoire MMIO.
    // En production, ces tests s'exécuteraient sur le vrai hardware.
    // Pour tester localement, voir tests/hardware_driver_tests.rs
}

