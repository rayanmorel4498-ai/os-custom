use spin::Mutex;
use crate::engine_modes::ai_orchestrator::{AIOrchestrator, ExecutionContext, ExecutionState};
use crate::r#loop::pipeline_executor::PipelineExecutor;
use crate::r#loop::loop_manager::LoopState;
use crate::modules::control::resource_quota::{AdmissionDecision, PriorityClass};
use crate::modules::runtime::{GlobalRuntimeServices, RuntimeServices};
use crate::utils::observability;

pub struct PrimaryLoop<S: RuntimeServices> {
    state: Mutex<LoopState>,
    services: S,
}

impl<S: RuntimeServices> PrimaryLoop<S> {
    pub fn new(services: S) -> Self {
        PrimaryLoop {
            state: Mutex::new(LoopState::new()),
            services,
        }
    }

    pub fn run(&self, timestamp_ms: u64, orchestrator: &AIOrchestrator, pipeline: &PipelineExecutor) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        let pending = orchestrator.get_pending_tasks();
        let mut processed = 0u32;
        for ctx in pending.iter().take(16) {
            let admission = self.is_over_module_quota(ctx);
            if admission == AdmissionDecision::Drop {
                processed += 1;
                continue;
            }
            if admission == AdmissionDecision::Throttle {
                observability::inc_quota_throttles();
                orchestrator.update_context_state(ctx.id, ExecutionState::Running);
                orchestrator.update_context_state(ctx.id, ExecutionState::Completed);
                orchestrator.record_decision(ctx.module_id, 0, 0.4);
                processed += 1;
                continue;
            }
            orchestrator.update_context_state(ctx.id, ExecutionState::Running);
            let pipeline_id = pipeline.create_pipeline(ctx.id);
            let _ = pipeline.progress_task(pipeline_id, 0);
            orchestrator.update_context_state(ctx.id, ExecutionState::Completed);
            orchestrator.record_decision(ctx.module_id, 0, 0.7);
            processed += 1;
        }

        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed += processed;
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }

    fn is_over_module_quota(&self, context: &ExecutionContext) -> AdmissionDecision {
        let module_key = alloc::format!("module:{}", context.module_id);
        let now_ms = self.services.now_ms(0);
        if let Some(decision) = self.services.degraded_override(&module_key, now_ms) {
            return decision;
        }
        let cpu_ms = Self::estimate_cpu_cost(context);
        let decision = self
            .services
            .quota_decision_and_record(&module_key, Self::priority_class(context.priority), cpu_ms, 0, now_ms);
        if decision != AdmissionDecision::Allow {
            self.services.degraded_record(&module_key, now_ms, decision);
        }
        decision
    }

    fn priority_class(priority: u8) -> PriorityClass {
        if priority >= 200 { PriorityClass::Realtime } else { PriorityClass::BestEffort }
    }

    fn estimate_cpu_cost(context: &ExecutionContext) -> u64 {
        let len = context.data.len() as u64;
        (len / 256).saturating_add(1)
    }
}

impl Default for PrimaryLoop<GlobalRuntimeServices> {
    fn default() -> Self {
        Self::new(GlobalRuntimeServices::new())
    }
}
