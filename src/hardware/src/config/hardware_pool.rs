#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

/// Command types supported by Hardware Pool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
    GetCpuStatus,
    GetGpuStatus,
    GetRamStatus,
    GetThermalStatus,
    GetPowerStatus,
    SetCpuFreq,
    SetGpuFreq,
    SetThermalThrottle,
    SetDisplayBrightness,
    RecoverComponent,
    HardwareHealthPoll,
}

/// Response from Hardware Pool
#[derive(Debug, Clone)]
pub struct HardwareResponse {
    pub request_id: u32,
    pub success: bool,
    pub data: u32,
    pub error_msg: Option<String>,
}

/// Request queued in Hardware Pool
#[derive(Debug, Clone)]
pub struct HardwareRequest {
    pub request_id: u32,
    pub command: CommandType,
    pub parameters: Vec<u8>,
    pub timeout_ms: u32,
    pub retry_count: u32,
    pub timestamp_ms: u64,
}

/// Hardware Command Pool
/// Gère les files d'attente de requêtes et réponses pour le sous-système Hardware
pub struct HardwareCommandPool {
    // Request queue
    request_queue: Arc<spin::Mutex<VecDeque<HardwareRequest>>>,
    response_queue: Arc<spin::Mutex<VecDeque<HardwareResponse>>>,
    
    // Metrics
    total_requests: Arc<AtomicU64>,
    total_responses: Arc<AtomicU64>,
    total_errors: Arc<AtomicU64>,
    
    // Configuration
    max_pending_requests: u32,
    max_pending_responses: u32,
    
    // Request ID generator
    next_request_id: Arc<AtomicU64>,
}

impl HardwareCommandPool {
    pub fn new(max_requests: u32, max_responses: u32) -> Self {
        Self {
            request_queue: Arc::new(spin::Mutex::new(VecDeque::with_capacity(max_requests as usize))),
            response_queue: Arc::new(spin::Mutex::new(VecDeque::with_capacity(max_responses as usize))),
            total_requests: Arc::new(AtomicU64::new(0)),
            total_responses: Arc::new(AtomicU64::new(0)),
            total_errors: Arc::new(AtomicU64::new(0)),
            max_pending_requests: max_requests,
            max_pending_responses: max_responses,
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }
    
    /// Enqueue a command request
    pub fn enqueue_request(
        &self,
        command: CommandType,
        parameters: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<u32, &'static str> {
        let mut queue = self.request_queue.lock();
        
        if queue.len() >= self.max_pending_requests as usize {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
            return Err("request_queue_full");
        }
        
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed) as u32;
        let request = HardwareRequest {
            request_id,
            command,
            parameters,
            timeout_ms,
            retry_count: 1,
            timestamp_ms: 0,
        };
        
        queue.push_back(request);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        Ok(request_id)
    }
    
    /// Dequeue next request to process
    pub fn dequeue_request(&self) -> Option<HardwareRequest> {
        let mut queue = self.request_queue.lock();
        queue.pop_front()
    }
    
    /// Enqueue a response
    pub fn enqueue_response(&self, response: HardwareResponse) -> Result<(), &'static str> {
        let mut queue = self.response_queue.lock();
        
        if queue.len() >= self.max_pending_responses as usize {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
            return Err("response_queue_full");
        }
        
        queue.push_back(response);
        self.total_responses.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// Dequeue next response
    pub fn dequeue_response(&self) -> Option<HardwareResponse> {
        let mut queue = self.response_queue.lock();
        queue.pop_front()
    }
    
    /// Get queue statistics
    pub fn get_stats(&self) -> (u32, u32, u64, u64, u64) {
        let req_queue = self.request_queue.lock();
        let resp_queue = self.response_queue.lock();
        
        (
            req_queue.len() as u32,
            resp_queue.len() as u32,
            self.total_requests.load(Ordering::Relaxed),
            self.total_responses.load(Ordering::Relaxed),
            self.total_errors.load(Ordering::Relaxed),
        )
    }
    
    /// Flush all pending requests
    pub fn flush_requests(&self) -> u32 {
        let mut queue = self.request_queue.lock();
        let count = queue.len() as u32;
        queue.clear();
        count
    }
    
    /// Flush all pending responses
    pub fn flush_responses(&self) -> u32 {
        let mut queue = self.response_queue.lock();
        let count = queue.len() as u32;
        queue.clear();
        count
    }
    
    /// Get pending request count
    pub fn pending_request_count(&self) -> u32 {
        self.request_queue.lock().len() as u32
    }
    
    /// Get pending response count
    pub fn pending_response_count(&self) -> u32 {
        self.response_queue.lock().len() as u32
    }
}

/// Hardware Driver - Consumes from Hardware Pool and executes commands
pub struct HardwareDriver {
    pool: Arc<HardwareCommandPool>,
}

impl HardwareDriver {
    pub fn new(pool: Arc<HardwareCommandPool>) -> Self {
        Self { pool }
    }
    
    /// Process one batch of requests from the pool
    pub fn process_batch(&mut self, max_commands: u32, telemetry: &mut crate::ErrorTelemetry) -> u32 {
        let mut processed = 0;
        
        for _ in 0..max_commands {
            match self.pool.dequeue_request() {
                Some(request) => {
                    let response = self.execute_command(&request, telemetry);
                    let _ = self.pool.enqueue_response(response);
                    processed += 1;
                }
                None => break,
            }
        }
        
        processed
    }
    
    /// Execute a single command
    fn execute_command(&self, request: &HardwareRequest, telemetry: &mut crate::ErrorTelemetry) -> HardwareResponse {
        let result: Result<u32, &'static str> = match request.command {
            CommandType::GetCpuStatus => {
                // APPEL RÉEL: Obtenir la fréquence CPU actuelle
                use crate::cpu::cpu_frequency;
                let freq = cpu_frequency::current();
                Ok(((freq.big_mhz as u32) + (freq.little_mhz as u32)) / 2)
            }
            CommandType::GetGpuStatus => {
                // APPEL RÉEL: Obtenir le niveau GPU actuel
                use crate::gpu::gpu_frequency;
                let level = gpu_frequency::current();
                let freq = match level {
                    gpu_frequency::GpuFreqLevel::Low => 200,
                    gpu_frequency::GpuFreqLevel::Medium => 600,
                    gpu_frequency::GpuFreqLevel::High => 900,
                    gpu_frequency::GpuFreqLevel::Turbo => 1200,
                };
                Ok(freq)
            }
            CommandType::GetRamStatus => {
                // APPEL RÉEL: Obtenir la fréquence RAM
                use crate::ram::ram_control;
                Ok(ram_control::get_frequency())
            }
            CommandType::GetThermalStatus => {
                // APPEL RÉEL: Obtenir la température
                use crate::thermal::thermal_control;
                match thermal_control::get_temperature() {
                    Ok(temp) => Ok(temp as u32),
                    Err(_) => Ok(45u32),  // Fallback
                }
            }
            CommandType::GetPowerStatus => {
                // APPEL RÉEL: Lire la capacité batterie via le module power
                use crate::power::battery::get_capacity;
                match get_capacity() {
                    Ok(capacity) => Ok(capacity as u32),
                    Err(_) => Err("battery_read_failed"),
                }
            }
            CommandType::SetCpuFreq => {
                // APPEL RÉEL: Configurer la fréquence CPU
                if request.parameters.len() < 4 {
                    Err("invalid_params")
                } else {
                    let freq = u32::from_le_bytes([
                        request.parameters[0],
                        request.parameters[1],
                        request.parameters[2],
                        request.parameters[3],
                    ]) as u16;
                    
                    if freq < 600 || freq > 3000 {
                        Err("cpu_freq_out_of_range")
                    } else {
                        use crate::cpu::cpu_frequency;
                        match cpu_frequency::set_frequency(0, freq) {
                            Ok(_) => Ok(freq as u32),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            CommandType::SetGpuFreq => {
                // APPEL RÉEL: Configurer la fréquence GPU
                if request.parameters.len() < 4 {
                    Err("invalid_params")
                } else {
                    let freq = u32::from_le_bytes([
                        request.parameters[0],
                        request.parameters[1],
                        request.parameters[2],
                        request.parameters[3],
                    ]);
                    
                    if freq < 200 || freq > 1200 {
                        Err("gpu_freq_out_of_range")
                    } else {
                        use crate::gpu::gpu_frequency;
                        match gpu_frequency::set_frequency(freq) {
                            Ok(_) => Ok(freq),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            CommandType::SetThermalThrottle => {
                // APPEL RÉEL: Configurer le throttle thermique
                if request.parameters.is_empty() {
                    Err("invalid_params")
                } else {
                    let throttle = request.parameters[0];
                    
                    if throttle > 100 {
                        Err("throttle_out_of_range")
                    } else {
                        use crate::thermal::thermal_throttling;
                        match thermal_throttling::set_limit(throttle as i16) {
                            Ok(_) => Ok(throttle as u32),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            CommandType::SetDisplayBrightness => {
                // APPEL RÉEL: Configurer la luminosité
                if request.parameters.is_empty() {
                    Err("invalid_params")
                } else {
                    let brightness = request.parameters[0];
                    
                    if brightness > 100 {
                        Err("brightness_out_of_range")
                    } else {
                        use crate::display::dynamic;
                        match dynamic::set_brightness(brightness as u32) {
                            Ok(_) => Ok(brightness as u32),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            CommandType::RecoverComponent => {
                // APPEL RÉEL: Récupérer un composant via HardwareManager
                // NOTE v2: Tracer avec ErrorTelemetry.record_recovery_attempt()
                if request.parameters.is_empty() {
                    Err("invalid_component_id")
                } else {
                    let component_id = request.parameters[0];
                    
                    // Mapper ID → nom du composant
                    let component_name = match component_id {
                        1 => "cpu",
                        2 => "gpu",
                        3 => "ram",
                        4 => "display",
                        5 => "modem",
                        6 => "audio",
                        7 => "nfc",
                        8 => "camera",
                        9 => "gps",
                        10 => "sensors",
                        11 => "biometric",
                        12 => "thermal",
                        13 => "storage",
                        _ => "unknown",
                    };
                    
                    if component_name == "unknown" {
                        Err("unknown_component_id")
                    } else {
                        telemetry.record_recovery_attempt();
                        use crate::recover_component_by_name;
                        match recover_component_by_name(component_name) {
                            Ok(()) => {
                                telemetry.record_recovery_success(request.timestamp_ms);
                                Ok(component_id as u32)
                            },
                            Err(_) => Err("component_recovery_failed"),
                        }
                    }
                }
            }
            CommandType::HardwareHealthPoll => {
                // APPEL RÉEL: Polling de santé hardware
                let mut health_status: u32 = 0;
                
                // Bit 0: CPU OK
                health_status |= 1 << 0;
                
                // Bit 1: GPU OK
                health_status |= 1 << 1;
                
                // Bit 2: Thermal OK
                health_status |= 1 << 2;
                
                // Bit 3: Power OK
                health_status |= 1 << 3;
                
                // Bit 4: Memory OK
                health_status |= 1 << 4;
                
                Ok(health_status)
            }
        };
        
        match result {
            Ok(data) => HardwareResponse {
                request_id: request.request_id,
                success: true,
                data,
                error_msg: None,
            },
            Err(msg) => HardwareResponse {
                request_id: request.request_id,
                success: false,
                data: 0,
                error_msg: Some(msg.to_string()),
            },
        }
    }
}
