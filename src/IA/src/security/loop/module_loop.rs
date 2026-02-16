use alloc::collections::{BTreeMap, VecDeque};
use crate::prelude::String;
 
use spin::Mutex;

use crate::core::ipc_bus::{BusEndpoint, IpcBus};
use crate::modules::app::app_prioritizer::AppUsage;
use crate::modules::monitoring::ui_visualization::UiVisualizer;
use crate::modules::profiling::gpu_auto_profile::SceneMetrics;
use crate::modules::sensors::sensor_manager::SensorContext;
use crate::modules::control::resource_quota::{AdmissionDecision, PriorityClass};
use crate::core::sandbox_controller::ActionType;
use crate::r#loop::loop_manager::LoopState;
use crate::modules::runtime::{GlobalRuntimeServices, RuntimeServices};
use crate::init::{
	with_adaptive_scheduler,
    with_app_prioritizer_api_mut,
    with_gpu_profiler_api_mut,
    with_sensor_api_mut,
};
use crate::utils::observability;
use crate::prelude::format;
use crate::utils::trace_buffer;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModulePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Clone, Copy)]
pub enum ModuleAction {
    SensorTick,
    AppPrioritizerTick,
    GpuProfileTick,
    UiSnapshot,
}

pub struct ModuleTask {
    pub module: &'static str,
    pub priority: ModulePriority,
    pub cpu_cost_ms: u64,
    pub gpu_cost_ms: u64,
    pub action: ModuleAction,
}

pub struct ModuleLoop<S: RuntimeServices> {
    state: Mutex<LoopState>,
    queue: Mutex<VecDeque<ModuleTask>>,
    failure_state: Mutex<BTreeMap<String, FailureWindow>>,
    services: S,
    max_queue: usize,
    max_tasks_per_tick: u32,
}

#[derive(Clone, Copy)]
struct FailureWindow {
    window_start_ms: u64,
    count: u32,
    last_action_ms: u64,
}

impl<S: RuntimeServices> ModuleLoop<S> {
    pub fn new(services: S) -> Self {
        ModuleLoop {
            state: Mutex::new(LoopState::new()),
            queue: Mutex::new(VecDeque::new()),
            failure_state: Mutex::new(BTreeMap::new()),
            services,
            max_queue: 256,
            max_tasks_per_tick: 8,
        }
    }

    pub fn submit(&self, task: ModuleTask) {
        let mut queue = self.queue.lock();
        if queue.len() >= self.max_queue {
            queue.pop_front();
        }
        let insert_at = queue
            .iter()
            .position(|t| task.priority > t.priority)
            .unwrap_or(queue.len());
        queue.insert(insert_at, task);
    }

    pub fn run(&self, timestamp_ms: u64, bus: &IpcBus) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        self.enqueue_default_tasks(timestamp_ms, bus);
        let mut processed = 0u32;
        let backlog = self.queue.lock().len() as i64;
        observability::set_gauge("module_queue_len", backlog);
        observability::set_gauge("trace_len", trace_buffer::trace_len() as i64);

        while processed < self.max_tasks_per_tick {
            let task = {
                let mut queue = self.queue.lock();
                queue.pop_front()
            };
            let Some(task) = task else { break; };

            if self.try_execute(task, timestamp_ms, bus) {
                processed += 1;
            }
        }

        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed = processed;
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }

    fn enqueue_default_tasks(&self, timestamp_ms: u64, bus: &IpcBus) {
        if bus.recv_command(BusEndpoint::Ia).is_some() {
            self.submit(ModuleTask {
                module: "ui",
                priority: self.adjusted_priority("ui", ModulePriority::Critical),
                cpu_cost_ms: 2,
                gpu_cost_ms: 0,
                action: ModuleAction::UiSnapshot,
            });
        }

        if bus.recv_event(BusEndpoint::Ia).is_some() {
            self.submit(ModuleTask {
                module: "ui",
                priority: self.adjusted_priority("ui", ModulePriority::High),
                cpu_cost_ms: 1,
                gpu_cost_ms: 0,
                action: ModuleAction::UiSnapshot,
            });
        }

        let phase = timestamp_ms % 1000;
        if phase < 200 {
            self.submit(ModuleTask {
                module: "sensors",
                priority: self.adjusted_priority("sensors", ModulePriority::High),
                cpu_cost_ms: 2,
                gpu_cost_ms: 0,
                action: ModuleAction::SensorTick,
            });
        }
        if phase < 600 {
            self.submit(ModuleTask {
                module: "apps",
                priority: self.adjusted_priority("apps", ModulePriority::Normal),
                cpu_cost_ms: 1,
                gpu_cost_ms: 0,
                action: ModuleAction::AppPrioritizerTick,
            });
        }
        self.submit(ModuleTask {
            module: "gpu",
            priority: self.adjusted_priority("gpu", ModulePriority::Normal),
            cpu_cost_ms: 1,
            gpu_cost_ms: 2,
            action: ModuleAction::GpuProfileTick,
        });
        self.submit(ModuleTask {
            module: "ui",
            priority: self.adjusted_priority("ui", ModulePriority::Low),
            cpu_cost_ms: 1,
            gpu_cost_ms: 0,
            action: ModuleAction::UiSnapshot,
        });
    }

    fn adjusted_priority(&self, module: &str, base: ModulePriority) -> ModulePriority {
        let (impact, criticality) = match module {
            "ui" => (1.0, 0.9),
            "apps" => {
                let impact = self.services.app_priority("home");
                (impact, 0.7)
            }
            "sensors" => (0.7, 0.8),
            "gpu" => (0.4, 0.5),
            _ => (0.5, 0.5),
        };
        let energy_pressure = self.services.energy_pressure();
        let score = with_adaptive_scheduler(|sched| sched.score(impact, criticality, energy_pressure))
            .unwrap_or(((0.55 * impact) + (0.35 * criticality) - (0.20 * energy_pressure)).clamp(0.0, 1.0));
        let delta = with_adaptive_scheduler(|sched| sched.priority_delta(score)).unwrap_or(0);
        self.apply_priority_delta(base, delta)
    }

    fn apply_priority_delta(&self, base: ModulePriority, delta: i32) -> ModulePriority {
        let mut value = base as i32 + delta;
        if value < ModulePriority::Low as i32 {
            value = ModulePriority::Low as i32;
        }
        if value > ModulePriority::Critical as i32 {
            value = ModulePriority::Critical as i32;
        }
        match value {
            0 => ModulePriority::Low,
            1 => ModulePriority::Normal,
            2 => ModulePriority::High,
            _ => ModulePriority::Critical,
        }
    }

    fn try_execute(&self, task: ModuleTask, timestamp_ms: u64, bus: &IpcBus) -> bool {
        let now_ms = self.services.now_ms(timestamp_ms);
        let policy_key = alloc::format!("module:{}", task.module);
        let decision = self.services.policy_decision(&policy_key);
        if matches!(decision, crate::core::policy_engine::PolicyDecision::Deny | crate::core::policy_engine::PolicyDecision::RequireConsent) {
            observability::inc_errors_total();
            trace_buffer::trace_event(format!("policy_block:{}", policy_key));
            self.record_failure(task.module, now_ms);
            self.maybe_recover(task.module, now_ms);
            return false;
        }
        let (action_type, io_ops) = match task.action {
            ModuleAction::SensorTick => (ActionType::DeviceControl, 0),
            ModuleAction::AppPrioritizerTick => (ActionType::SystemIntegrity, 0),
            ModuleAction::GpuProfileTick => (ActionType::KernelCPU, 0),
            ModuleAction::UiSnapshot => (ActionType::CommunicationSend, 1),
        };
        if !self.services.sandbox_validate_action(task.module, action_type, task.cpu_cost_ms, 0, io_ops) {
            observability::inc_errors_total();
            trace_buffer::trace_event(format!("sandbox_block:{}", task.module));
            self.record_failure(task.module, now_ms);
            self.maybe_recover(task.module, now_ms);
            return false;
        }
        if let Some(decision) = self.services.degraded_override(task.module, now_ms) {
            if matches!(decision, AdmissionDecision::Throttle | AdmissionDecision::Drop) {
                if matches!(decision, AdmissionDecision::Throttle) {
                    observability::inc_quota_throttles();
                }
                return false;
            }
        }
        let priority = match task.priority {
            ModulePriority::Critical | ModulePriority::High => PriorityClass::Realtime,
            ModulePriority::Normal | ModulePriority::Low => PriorityClass::BestEffort,
        };
        let decision = self
            .services
            .quota_decision_and_record(task.module, priority, task.cpu_cost_ms, task.gpu_cost_ms, now_ms);
        let allowed = match decision {
            AdmissionDecision::Allow | AdmissionDecision::Throttle => {
                if matches!(decision, AdmissionDecision::Throttle) {
                    observability::inc_quota_throttles();
                }
                if decision != AdmissionDecision::Allow {
                    self.services.degraded_record(task.module, now_ms, decision);
                }
                true
            }
            AdmissionDecision::Drop => false,
        };

        if !allowed {
            trace_buffer::trace_event(format!("quota_drop:{}", task.module));
            self.record_failure(task.module, now_ms);
            self.maybe_recover(task.module, now_ms);
            return false;
        }

        match task.action {
            ModuleAction::SensorTick => {
                let _ = with_sensor_api_mut(|mgr| {
                    mgr.register("gps");
                    mgr.register("gyro");
                    mgr.register("mic");
                    let ctx = SensorContext {
                        battery_level: (timestamp_ms % 100) as u8,
                        temperature_c: 28.0 + ((timestamp_ms % 30) as f32),
                        motion_active: (timestamp_ms % 2) == 0,
                        screen_on: (timestamp_ms % 3) != 0,
                    };
                    mgr.apply_context(ctx);
                });
            }
            ModuleAction::AppPrioritizerTick => {
                let _ = with_app_prioritizer_api_mut(|apps| {
                    let usage = AppUsage {
                        perceived_latency_ms: (timestamp_ms % 60) as f32,
                        foreground_time_ms: 1500 + (timestamp_ms % 400),
                        background_time_ms: 300 + (timestamp_ms % 200),
                    };
                    apps.update_usage("home", usage);
                });
            }
            ModuleAction::GpuProfileTick => {
                let _ = with_gpu_profiler_api_mut(|gpu| {
                    let metrics = SceneMetrics {
                        triangles_k: (timestamp_ms % 3000) as u32,
                        frame_time_ms: 10.0 + ((timestamp_ms % 20) as f32),
                        ui_active: true,
                    };
                    let _ = gpu.update(metrics);
                });
            }
            ModuleAction::UiSnapshot => {
                UiVisualizer::emit_snapshot(bus, timestamp_ms);
            }
        }

        self.clear_failure(task.module);

        true
    }

    fn record_failure(&self, module: &str, now_ms: u64) {
        let mut state = self.failure_state.lock();
        let entry = state.entry(module.into()).or_insert(FailureWindow {
            window_start_ms: now_ms,
            count: 0,
            last_action_ms: 0,
        });
        if now_ms.saturating_sub(entry.window_start_ms) > 5_000 {
            entry.window_start_ms = now_ms;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
    }

    fn maybe_recover(&self, module: &str, now_ms: u64) {
        let mut state = self.failure_state.lock();
        let entry = match state.get_mut(module) {
            Some(e) => e,
            None => return,
        };
        let count = entry.count;
        if count >= 6 && now_ms.saturating_sub(entry.last_action_ms) > 2_000 {
            entry.last_action_ms = now_ms;
            drop(state);
            self.services.request_rollback(module, now_ms);
            return;
        }
        if count >= 3 && now_ms.saturating_sub(entry.last_action_ms) > 1_000 {
            entry.last_action_ms = now_ms;
            drop(state);
            self.services.request_restart(module, now_ms);
        }
    }

    fn clear_failure(&self, module: &str) {
        self.failure_state.lock().remove(module);
    }
}

impl ModuleLoop<GlobalRuntimeServices> {
    pub fn new_default() -> Self {
        Self::new(GlobalRuntimeServices::new())
    }
}

impl Default for ModuleLoop<GlobalRuntimeServices> {
    fn default() -> Self {
        Self::new_default()
    }
}
