use spin::Mutex;
use crate::prelude::String;
use crate::core::ai_orchestrator::AIOrchestrator;
use crate::r#loop::pipeline_executor::PipelineExecutor;
use crate::core::tls_integration::TLSIntegrationManager;
use crate::core::global_state::GlobalStateManager;
use crate::r#loop::primary_loop::PrimaryLoop;
use crate::r#loop::secondary_loop::SecondaryLoop;
use crate::r#loop::thirth_loop::ThirthLoop;
use crate::r#loop::external_loop::ExternalLoop;
use crate::r#loop::utility_loop::UtilityLoop;
use crate::core::ai_watchdog::AIHealth;
use crate::core::safe_ai::SafeAIAction;
use crate::core::init::{
    with_anomaly_detector,
    with_auto_repair_mut,
    with_model_cache,
    with_safe_ai_mut,
    with_watchdog_mut,
};

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
    primary_loop: PrimaryLoop,
    secondary_loop: SecondaryLoop,
    thirth_loop: ThirthLoop,
    external_loop: ExternalLoop,
    utility_loop: UtilityLoop,
    state: Mutex<LoopState>,
    profiling: Mutex<LoopProfiling>,
}

impl LoopManager {
    pub fn new() -> Self {
        LoopManager {
            primary_loop: PrimaryLoop::new(),
            secondary_loop: SecondaryLoop::new(),
            thirth_loop: ThirthLoop::new(),
            external_loop: ExternalLoop::new(),
            utility_loop: UtilityLoop::new(),
            state: Mutex::new(LoopState::new()),
            profiling: Mutex::new(LoopProfiling::new()),
        }
    }

    pub fn run_all(
        &self,
        timestamp_ms: u64,
        orchestrator: &AIOrchestrator,
        pipeline: &PipelineExecutor,
        tls: &TLSIntegrationManager,
        global_state: &GlobalStateManager,
    ) {
        self.primary_loop.run(timestamp_ms, orchestrator, pipeline);
        self.secondary_loop.run(timestamp_ms, orchestrator, pipeline);
        self.thirth_loop.run(timestamp_ms, tls);
        self.external_loop.run(timestamp_ms, global_state);
        self.utility_loop.run(timestamp_ms);

        let mut state = self.state.lock();
        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed = self.primary_loop.get_state().processed
            + self.secondary_loop.get_state().processed
            + self.thirth_loop.get_state().processed
            + self.external_loop.get_state().processed
            + self.utility_loop.get_state().processed;

        let mut profiling = self.profiling.lock();
        profiling.update(
            timestamp_ms,
            self.primary_loop.get_state().processed,
            self.secondary_loop.get_state().processed,
            self.thirth_loop.get_state().processed,
            self.external_loop.get_state().processed,
            self.utility_loop.get_state().processed,
        );

        let diag = self.secondary_loop.get_diagnostics();
        let health = with_watchdog_mut(|wd| wd.update(diag, *self.profiling.lock()))
            .unwrap_or(AIHealth::Healthy);
        let alerts = with_anomaly_detector(|det| det.recent_alerts(3)).unwrap_or_default();
        let action = with_safe_ai_mut(|safe| safe.update_escalation(health, &alerts, timestamp_ms))
            .unwrap_or(SafeAIAction::None);
        match action {
            SafeAIAction::PurgeCache => {
                let _ = with_model_cache(|cache| {
                    let _ = with_auto_repair_mut(|repair| repair.purge_caches(timestamp_ms, cache));
                });
            }
            SafeAIAction::RollbackConfig => {
                let _ = with_auto_repair_mut(|repair| repair.rollback_config(timestamp_ms));
            }
            SafeAIAction::None => {}
        }
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
}

impl Default for LoopManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct LoopProfiling {
    pub last_tick_ms: u64,
    pub avg_tick_interval_ms: f32,
    pub primary_processed: u32,
    pub secondary_processed: u32,
    pub thirth_processed: u32,
    pub external_processed: u32,
    pub utility_processed: u32,
    pub ema_alpha: f32,
}

impl LoopProfiling {
    pub fn new() -> Self {
        LoopProfiling {
            last_tick_ms: 0,
            avg_tick_interval_ms: 0.0,
            primary_processed: 0,
            secondary_processed: 0,
            thirth_processed: 0,
            external_processed: 0,
            utility_processed: 0,
            ema_alpha: 0.1,
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
            self.avg_tick_interval_ms =
                self.ema_alpha * interval + (1.0 - self.ema_alpha) * self.avg_tick_interval_ms;
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
