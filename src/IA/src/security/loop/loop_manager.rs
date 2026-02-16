use spin::Mutex;
use crate::prelude::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use crate::core::ai_orchestrator::AIOrchestrator;
use crate::r#loop::pipeline_executor::PipelineExecutor;
use crate::core::tls_integration::TLSIntegrationManager;
use crate::core::global_state::GlobalStateManager;
use crate::r#loop::primary_loop::PrimaryLoop;
use crate::r#loop::secondary_loop::SecondaryLoop;
use crate::r#loop::thirth_loop::ThirthLoop;
use crate::r#loop::external_loop::ExternalLoop;
use crate::r#loop::utility_loop::UtilityLoop;
use crate::r#loop::module_loop::ModuleLoop;
use crate::modules::runtime::GlobalRuntimeServices;
use crate::utils::observability;
use crate::init::with_cache_api;

#[derive(Clone, Copy)]
pub struct LoopState {
    pub enabled: bool,
    pub iterations: u64,
    pub last_tick_ms: u64,
    pub processed: u32,
}

impl LoopState {
    pub fn new() -> Self {
        LoopState {
            enabled: true,
            iterations: 0,
            last_tick_ms: 0,
            processed: 0,
        }
    }
}

pub struct LoopManager {
    primary_loop: PrimaryLoop<GlobalRuntimeServices>,
    secondary_loop: SecondaryLoop<GlobalRuntimeServices>,
    thirth_loop: ThirthLoop,
    external_loop: ExternalLoop,
    utility_loop: UtilityLoop,
    module_loop: ModuleLoop<GlobalRuntimeServices>,
    state: Mutex<LoopState>,
    profiling: Mutex<LoopProfiling>,
    observability: Mutex<LoopObservability>,
}

impl LoopManager {
    pub fn new() -> Self {
        LoopManager {
            primary_loop: PrimaryLoop::new(GlobalRuntimeServices::new()),
            secondary_loop: SecondaryLoop::new(GlobalRuntimeServices::new()),
            thirth_loop: ThirthLoop::new(),
            external_loop: ExternalLoop::new(),
            utility_loop: UtilityLoop::new(),
            module_loop: ModuleLoop::new(GlobalRuntimeServices::new()),
            state: Mutex::new(LoopState::new()),
            profiling: Mutex::new(LoopProfiling::new()),
            observability: Mutex::new(LoopObservability::new()),
        }
    }

    pub fn run_all(
        &self,
        timestamp_ms: u64,
        orchestrator: &AIOrchestrator,
        pipeline: &PipelineExecutor,
        tls: &TLSIntegrationManager,
        global_state: &GlobalStateManager,
        bus: &crate::core::ipc_bus::IpcBus,
    ) {
        self.primary_loop.run(timestamp_ms, orchestrator, pipeline);
        self.secondary_loop.run(timestamp_ms, orchestrator, pipeline);
        self.thirth_loop.run(timestamp_ms, tls);
        self.external_loop.run(timestamp_ms, global_state);
        self.utility_loop.run(timestamp_ms);
        self.module_loop.run(timestamp_ms, bus);

        let mut state = self.state.lock();
        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed = self.primary_loop.get_state().processed
            + self.secondary_loop.get_state().processed
            + self.thirth_loop.get_state().processed
            + self.external_loop.get_state().processed
            + self.utility_loop.get_state().processed
            + self.module_loop.get_state().processed;

        let mut profiling = self.profiling.lock();
        profiling.update(
            timestamp_ms,
            self.primary_loop.get_state().processed,
            self.secondary_loop.get_state().processed,
            self.thirth_loop.get_state().processed,
            self.external_loop.get_state().processed,
            self.utility_loop.get_state().processed,
        );

        let mut obs = self.observability.lock();
        obs.ticks = state.iterations;
        obs.avg_tick_interval_ms = profiling.avg_tick_interval_ms;
        observability::set_ticks(obs.ticks);
        observability::set_avg_latency_ms(obs.avg_tick_interval_ms);
        observability::set_loop_latency_ms(profiling.last_tick_interval_ms);
        observability::set_loop_latency_p95_ms(profiling.p95_tick_interval_ms);
        observability::set_loop_latency_p99_ms(profiling.p99_tick_interval_ms);
        observability::set_loop_jitter_ms(profiling.jitter_ema_ms);
        let _ = with_cache_api(|cache| {
            let (_count, current_bytes, utilization) = cache.get_cache_stats();
            observability::set_gauge("model_cache_bytes", current_bytes as i64);
            observability::set_gauge("model_cache_util_milli", (utilization * 10.0) as i64);
        });

    }

    pub fn get_secondary_diagnostics(&self) -> crate::r#loop::secondary_loop::LoopDiagnostics {
        self.secondary_loop.get_diagnostics()
    }

    pub fn get_profiling(&self) -> LoopProfiling {
        *self.profiling.lock()
    }

    pub fn export_profiling(&self) -> String {
        self.profiling.lock().export()
    }

    pub fn record_safe_ai_action(&self, action: crate::core::safe_ai::SafeAIAction) {
        if action != crate::core::safe_ai::SafeAIAction::None {
            let mut obs = self.observability.lock();
            obs.safe_ai_actions = obs.safe_ai_actions.saturating_add(1);
            observability::inc_safe_ai_actions();
        }
    }

    pub fn record_error(&self) {
        let mut obs = self.observability.lock();
        obs.errors = obs.errors.saturating_add(1);
        observability::inc_errors_total();
    }

    pub fn export_observability(&self) -> String {
        self.observability.lock().export()
    }
}

impl Default for LoopManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct LoopProfiling {
    pub last_tick_ms: u64,
    pub last_tick_interval_ms: f32,
    pub avg_tick_interval_ms: f32,
    pub p95_tick_interval_ms: f32,
    pub p99_tick_interval_ms: f32,
    pub jitter_ema_ms: f32,
    pub primary_processed: u32,
    pub secondary_processed: u32,
    pub thirth_processed: u32,
    pub external_processed: u32,
    pub utility_processed: u32,
    pub ema_alpha: f32,
    interval_window: [f32; 64],
    window_idx: usize,
    window_len: usize,
}

#[derive(Clone, Copy)]
pub struct LoopObservability {
    pub ticks: u64,
    pub avg_tick_interval_ms: f32,
    pub safe_ai_actions: u64,
    pub errors: u64,
}

impl LoopObservability {
    pub fn new() -> Self {
        LoopObservability {
            ticks: 0,
            avg_tick_interval_ms: 0.0,
            safe_ai_actions: 0,
            errors: 0,
        }
    }

    pub fn export(&self) -> String {
        alloc::format!(
            "ticks={},avg_tick_ms={:.2},errors={},safe_ai_actions={}",
            self.ticks,
            self.avg_tick_interval_ms,
            self.errors,
            self.safe_ai_actions
        )
    }
}

impl LoopProfiling {
    pub fn new() -> Self {
        LoopProfiling {
            last_tick_ms: 0,
            last_tick_interval_ms: 0.0,
            avg_tick_interval_ms: 0.0,
            p95_tick_interval_ms: 0.0,
            p99_tick_interval_ms: 0.0,
            jitter_ema_ms: 0.0,
            primary_processed: 0,
            secondary_processed: 0,
            thirth_processed: 0,
            external_processed: 0,
            utility_processed: 0,
            ema_alpha: 0.1,
            interval_window: [0.0; 64],
            window_idx: 0,
            window_len: 0,
        }
    }

    pub fn update(
        &mut self,
        timestamp_ms: u64,
        primary_processed: u32,
        secondary_processed: u32,
        thirth_processed: u32,
        external_processed: u32,
        utility_processed: u32,
    ) {
        if self.last_tick_ms > 0 && timestamp_ms >= self.last_tick_ms {
            let interval = (timestamp_ms - self.last_tick_ms) as f32;
            self.last_tick_interval_ms = interval;
            self.avg_tick_interval_ms =
                self.ema_alpha * interval + (1.0 - self.ema_alpha) * self.avg_tick_interval_ms;

            let jitter = (interval - self.avg_tick_interval_ms).abs();
            self.jitter_ema_ms =
                self.ema_alpha * jitter + (1.0 - self.ema_alpha) * self.jitter_ema_ms;

            self.interval_window[self.window_idx] = interval;
            self.window_idx = (self.window_idx + 1) % self.interval_window.len();
            self.window_len = self.window_len.saturating_add(1).min(self.interval_window.len());

            if self.window_len > 0 {
                let mut sorted: Vec<f32> = self.interval_window[..self.window_len].to_vec();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
                let last = self.window_len - 1;
                let p95_idx = (last * 95) / 100;
                let p99_idx = (last * 99) / 100;
                self.p95_tick_interval_ms = sorted[p95_idx];
                self.p99_tick_interval_ms = sorted[p99_idx];
            }
        }
        self.last_tick_ms = timestamp_ms;
        self.primary_processed = primary_processed;
        self.secondary_processed = secondary_processed;
        self.thirth_processed = thirth_processed;
        self.external_processed = external_processed;
        self.utility_processed = utility_processed;
    }

    pub fn export(&self) -> String {
        alloc::format!(
            "tick_avg_ms={:.2}, primary={}, secondary={}, thirth={}, external={}, utility={}",
            self.avg_tick_interval_ms,
            self.primary_processed,
            self.secondary_processed,
            self.thirth_processed,
            self.external_processed,
            self.utility_processed
        )
    }
}
