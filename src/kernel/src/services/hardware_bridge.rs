use alloc::sync::Arc;
use alloc::string::String;
use alloc::collections::VecDeque;
use parking_lot::Mutex;
use redmi_hardware::config::{HardwareCommandPool, CommandType};

pub enum HardwareMessage {
    GetCpuStatus,
    GetGpuStatus,
    GetRamStatus,
    GetPowerStatus,
    GetThermalStatus,
}

pub enum HardwareResponse {
    Success(u32),
    Error(String),
    Timeout,
}

pub struct MessageRequest {
    pub id: u64,
    pub message: HardwareMessage,
}

pub struct MessageReply {
    pub id: u64,
    pub response: HardwareResponse,
}

pub struct HardwareDriver {
    pub request_queue: Arc<Mutex<VecDeque<MessageRequest>>>,
    pub reply_queue: Arc<Mutex<VecDeque<MessageReply>>>,
    pub hardware_pool: Option<Arc<HardwareCommandPool>>,
}

impl HardwareDriver {
    pub fn new() -> Self {
        Self {
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            reply_queue: Arc::new(Mutex::new(VecDeque::new())),
            hardware_pool: None,
        }
    }

    pub fn with_pool(pool: Arc<HardwareCommandPool>) -> Self {
        Self {
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            reply_queue: Arc::new(Mutex::new(VecDeque::new())),
            hardware_pool: Some(pool),
        }
    }

    pub fn process_request(&self) -> Option<MessageReply> {
        let request = {
            let mut queue = self.request_queue.lock();
            queue.pop_front()
        };

        request.map(|request| {
            let response = if let Some(pool) = &self.hardware_pool {
                let cmd = match request.message {
                    HardwareMessage::GetCpuStatus => CommandType::GetCpuStatus,
                    HardwareMessage::GetGpuStatus => CommandType::GetGpuStatus,
                    HardwareMessage::GetRamStatus => CommandType::GetRamStatus,
                    HardwareMessage::GetPowerStatus => CommandType::GetPowerStatus,
                    HardwareMessage::GetThermalStatus => CommandType::GetThermalStatus,
                };

                if pool.enqueue_request(cmd, alloc::vec![], 5000).is_ok() {
                    pool.dequeue_response()
                        .map(|resp| {
                            if resp.success {
                                HardwareResponse::Success(resp.data)
                            } else {
                                HardwareResponse::Error(resp.error_msg.unwrap_or_else(|| "error".into()))
                            }
                        })
                        .unwrap_or(HardwareResponse::Timeout)
                } else {
                    HardwareResponse::Error("enqueue failed".into())
                }
            } else {
                match request.message {
                    HardwareMessage::GetCpuStatus => HardwareResponse::Success(8),
                    HardwareMessage::GetGpuStatus => HardwareResponse::Success(900),
                    HardwareMessage::GetRamStatus => HardwareResponse::Success(8192),
                    HardwareMessage::GetPowerStatus => HardwareResponse::Success(100),
                    HardwareMessage::GetThermalStatus => HardwareResponse::Success(45),
                }
            };

            let reply = MessageReply {
                id: request.id,
                response,
            };

            self.reply_queue.lock().push_back(reply.clone());
            reply
        })
    }

    pub fn drain_and_process(&self) -> usize {
        let mut count = 0;
        while self.process_request().is_some() {
            count += 1;
        }
        count
    }

    pub fn register_with_primary_loop(
        &self,
        primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
    ) -> Result<(), String> {
        let _ = primary_loop;
        Ok(())
    }
}

impl Clone for MessageReply {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            response: match &self.response {
                HardwareResponse::Success(v) => HardwareResponse::Success(*v),
                HardwareResponse::Error(e) => HardwareResponse::Error(e.clone()),
                HardwareResponse::Timeout => HardwareResponse::Timeout,
            },
        }
    }
}

pub struct HardwareBridge {
    primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
    driver: Arc<HardwareDriver>,
    timeout_ms: u64,
    request_counter: Arc<Mutex<u64>>,
}

impl HardwareBridge {
    pub fn new(
        primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
    ) -> Result<Self, String> {
        let hardware_sessions = primary_loop.get_hardware_sessions();
        if hardware_sessions.is_empty() {
            return Err(String::from("No hardware available"));
        }

        let driver = Arc::new(HardwareDriver::new());
        driver.register_with_primary_loop(primary_loop.clone())?;

        Ok(Self {
            primary_loop,
            driver,
            timeout_ms: 5000,
            request_counter: Arc::new(Mutex::new(0)),
        })
    }

    pub fn with_pool(
        primary_loop: Arc<redmi_tls::runtime::loops::primary_loop::PrimaryLoop>,
        pool: Arc<HardwareCommandPool>,
    ) -> Result<Self, String> {
        let hardware_sessions = primary_loop.get_hardware_sessions();
        if hardware_sessions.is_empty() {
            return Err(String::from("No hardware available"));
        }

        let driver = Arc::new(HardwareDriver::with_pool(pool));
        driver.register_with_primary_loop(primary_loop.clone())?;

        Ok(Self {
            primary_loop,
            driver,
            timeout_ms: 5000,
            request_counter: Arc::new(Mutex::new(0)),
        })
    }

    pub fn send_message(&self, message: HardwareMessage, token: &str) -> Result<HardwareResponse, String> {
        if !self.primary_loop.is_kernel_or_hardware_token(token) {
            return Err("TLS refused hardware command".into());
        }
        let mut counter = self.request_counter.lock();
        *counter = counter.wrapping_add(1);
        let request_id = *counter;
        drop(counter);

        let request = MessageRequest {
            id: request_id,
            message,
        };

        self.driver.request_queue.lock().push_back(request);

        let _ = self.primary_loop.trigger_health_poll(request_id);

        let mut spins = 0u64;
        let max_spins = self.timeout_ms.saturating_mul(1000);

        while spins < max_spins {
            let reply = { self.driver.reply_queue.lock().pop_front() };
            if let Some(reply) = reply {
                if reply.id == request_id {
                    return Ok(reply.response);
                } else {
                    self.driver.reply_queue.lock().push_back(reply);
                }
            }

            spins = spins.saturating_add(1);
            core::hint::spin_loop();
        }

        Ok(HardwareResponse::Timeout)
    }

    pub fn send_message_async(
        &self,
        message: HardwareMessage,
        token: &str,
    ) -> Result<HardwareResponse, String> {
        if !self.primary_loop.is_kernel_or_hardware_token(token) {
            return Err("TLS refused hardware command".into());
        }
        let hardware_sessions = self.primary_loop.get_hardware_sessions();
        
        if hardware_sessions.is_empty() {
            return Ok(HardwareResponse::Error("No hardware available".into()));
        }

        let mut counter = self.request_counter.lock();
        *counter = counter.wrapping_add(1);
        let request_id = *counter;
        drop(counter);

        let request = MessageRequest {
            id: request_id,
            message,
        };

        self.driver.request_queue.lock().push_back(request);

        let _ = self.primary_loop.trigger_health_poll(request_id);

        let response = match self.driver.reply_queue.lock().pop_front() {
            Some(reply) if reply.id == request_id => reply.response,
            Some(reply) => {
                self.driver.reply_queue.lock().push_back(reply);
                HardwareResponse::Timeout
            }
            None => HardwareResponse::Timeout,
        };

        Ok(response)
    }

    pub fn get_hardware_count(&self) -> usize {
        self.primary_loop.get_hardware_sessions().len()
    }

    pub fn verify_hardware_available(&self) -> bool {
        !self.primary_loop.get_hardware_sessions().is_empty()
    }

    pub fn set_timeout_ms(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
    }

    pub fn process_pending_hardware_requests(&self) -> usize {
        self.driver.drain_and_process()
    }
}
