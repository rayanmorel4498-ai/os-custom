use spin::Mutex;
use crate::core::ai_orchestrator::{AIOrchestrator, ExecutionState};
use crate::r#loop::pipeline_executor::PipelineExecutor;
use crate::r#loop::loop_manager::LoopState;
use crate::core::init::{with_resource_quota_mut, with_timekeeper};
use crate::core::resource_quota::{AdmissionDecision, PriorityClass};

pub struct PrimaryLoop {
    state: Mutex<LoopState>,
}

impl PrimaryLoop {
    pub fn new() -> Self {
        PrimaryLoop {
            state: Mutex::new(LoopState::new()),
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

    fn is_over_module_quota(&self, context: &crate::core::ai_orchestrator::ExecutionContext) -> AdmissionDecision {
        let module_key = alloc::format!("module:{}", context.module_id);
        let now_ms = with_timekeeper(|tk| tk.now_ms()).unwrap_or(0);
        let cpu_ms = Self::estimate_cpu_cost(context);
        with_resource_quota_mut(|quota| {
            quota.record_cpu(&module_key, cpu_ms, now_ms);
            quota.record_latency(&module_key, cpu_ms);
            quota.admission_decision(&module_key, Self::priority_class(context.priority))
        }).unwrap_or(AdmissionDecision::Allow)
    }

    fn priority_class(priority: u8) -> PriorityClass {
        if priority >= 200 { PriorityClass::Realtime } else { PriorityClass::BestEffort }
    }

    fn estimate_cpu_cost(context: &crate::core::ai_orchestrator::ExecutionContext) -> u64 {
        let len = context.data.len() as u64;
        (len / 256).saturating_add(1)
    }
}

impl Default for PrimaryLoop {
    fn default() -> Self {
        Self::new()
    }
}
