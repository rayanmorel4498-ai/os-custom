use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::core::ai_orchestrator::{ExecutionState, ContextId};

#[derive(Debug, Clone)]
pub enum PipelineStage {
    Input,
    Preprocessing,
    Analysis,
    Learning,
    Decision,
    Action,
    Output,
}

#[derive(Debug, Clone)]
pub struct PipelineTask {
    pub stage: PipelineStage,
    pub task_id: u32,
    pub context_id: ContextId,
    pub state: ExecutionState,
}

#[derive(Debug, Clone)]
pub struct PipelineMetrics {
    pub total_processed: u32,
    pub total_failed: u32,
    pub average_latency_ms: u32,
    pub throughput: f32,
}

pub struct PipelineExecutor {
    stages: Mutex<BTreeMap<u32, Vec<PipelineTask>>>,
    metrics: Mutex<PipelineMetrics>,
    task_counter: Mutex<u32>,
}

impl PipelineExecutor {
    pub fn new() -> Self {
        PipelineExecutor {
            stages: Mutex::new(BTreeMap::new()),
            metrics: Mutex::new(PipelineMetrics {
                total_processed: 0,
                total_failed: 0,
                average_latency_ms: 0,
                throughput: 0.0,
            }),
            task_counter: Mutex::new(0),
        }
    }

    pub fn create_pipeline(&self, context_id: ContextId) -> u32 {
        let mut counter = self.task_counter.lock();
        let task_id = *counter;
        *counter += 1;

        let mut stages = self.stages.lock();

        let input_task = PipelineTask {
            stage: PipelineStage::Input,
            task_id,
            context_id,
            state: ExecutionState::Pending,
        };

        stages.entry(0).or_insert_with(Vec::new).push(input_task);

        task_id
    }

    pub fn progress_task(&self, task_id: u32, current_stage: u32) -> Option<u32> {
        let mut stages = self.stages.lock();

        let mut next_stage = None;

        if let Some(tasks) = stages.get_mut(&current_stage) {
            for task in tasks.iter_mut() {
                if task.task_id == task_id {
                    task.state = ExecutionState::Completed;
                    next_stage = Some(current_stage + 1);
                    break;
                }
            }
        }

        if let Some(ns) = next_stage {
            if ns <= 6 {
                let new_task = PipelineTask {
                    stage: match ns {
                        0 => PipelineStage::Input,
                        1 => PipelineStage::Preprocessing,
                        2 => PipelineStage::Analysis,
                        3 => PipelineStage::Learning,
                        4 => PipelineStage::Decision,
                        5 => PipelineStage::Action,
                        _ => PipelineStage::Output,
                    },
                    task_id,
                    context_id: 0,
                    state: ExecutionState::Pending,
                };

                stages.entry(ns).or_insert_with(Vec::new).push(new_task);
                Some(ns)
            } else {
                self.finalize_task(task_id);
                None
            }
        } else {
            None
        }
    }

    pub fn finalize_task(&self, _task_id: u32) {
        let mut metrics = self.metrics.lock();
        metrics.total_processed += 1;
    }

    pub fn fail_task(&self, _task_id: u32) {
        let mut metrics = self.metrics.lock();
        metrics.total_failed += 1;
    }

    pub fn get_stage_tasks(&self, stage: u32) -> Vec<PipelineTask> {
        let stages = self.stages.lock();
        stages.get(&stage)
            .map(|tasks| tasks.clone())
            .unwrap_or_default()
    }

    pub fn get_pending_at_stage(&self, stage: u32) -> Vec<PipelineTask> {
        let stages = self.stages.lock();
        stages.get(&stage)
            .map(|tasks| {
                tasks.iter()
                    .filter(|t| t.state == ExecutionState::Pending)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_metrics(&self) -> PipelineMetrics {
        self.metrics.lock().clone()
    }

    pub fn update_latency(&self, latency_ms: u32) {
        let mut metrics = self.metrics.lock();
        let prev_total = metrics.total_processed;
        let prev_avg = metrics.average_latency_ms;

        if prev_total > 0 {
            metrics.average_latency_ms = (prev_avg * prev_total as u32 + latency_ms) / (prev_total as u32 + 1);
        } else {
            metrics.average_latency_ms = latency_ms;
        }
    }

    pub fn calculate_throughput(&self) -> f32 {
        let metrics = self.metrics.lock();
        if metrics.average_latency_ms > 0 {
            1000.0 / metrics.average_latency_ms as f32
        } else {
            0.0
        }
    }

    pub fn get_pipeline_stages(&self) -> Vec<(u32, u32)> {
        let stages = self.stages.lock();
        stages.iter()
            .map(|(&stage, tasks)| (stage, tasks.len() as u32))
            .collect()
    }

    pub fn parallel_process_stage(&self, stage: u32, batch_size: u32) -> u32 {
        let pending = self.get_pending_at_stage(stage);
        let mut processed = 0;

        for task in pending.iter().take(batch_size as usize) {
            self.progress_task(task.task_id, stage);
            processed += 1;
        }

        processed
    }
}
