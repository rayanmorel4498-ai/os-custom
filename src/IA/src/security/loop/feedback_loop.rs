use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::core::ai_orchestrator::{Decision, ModuleId};

#[derive(Debug, Clone)]
pub enum FeedbackType {
    Success,
    Partial,
    Failed,
}

#[derive(Debug, Clone)]
pub struct DecisionFeedback {
    pub decision: Decision,
    pub result: FeedbackType,
    pub reward: f32,
    pub source_module: ModuleId,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct LearningMetrics {
    pub total_decisions: u32,
    pub successful: u32,
    pub failed: u32,
    pub avg_reward: f32,
    pub learning_progress: f32,
}

#[derive(Debug, Clone)]
pub struct RuleAdjustment {
    pub rule_id: u32,
    pub weight_delta: f32,
    pub confidence_change: f32,
}

pub struct FeedbackLoop {
    feedback_history: Mutex<Vec<DecisionFeedback>>,
    learning_metrics: Mutex<LearningMetrics>,
    rule_adjustments: Mutex<BTreeMap<u32, f32>>,
    learning_rate: Mutex<f32>,
    decision_quality: Mutex<BTreeMap<Decision, f32>>,
}

impl FeedbackLoop {
    pub fn new() -> Self {
        FeedbackLoop {
            feedback_history: Mutex::new(Vec::new()),
            learning_metrics: Mutex::new(LearningMetrics {
                total_decisions: 0,
                successful: 0,
                failed: 0,
                avg_reward: 0.0,
                learning_progress: 0.0,
            }),
            rule_adjustments: Mutex::new(BTreeMap::new()),
            learning_rate: Mutex::new(0.01),
            decision_quality: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn record_feedback(&self, feedback: DecisionFeedback) {
        let mut history = self.feedback_history.lock();
        history.push(feedback.clone());

        let mut metrics = self.learning_metrics.lock();
        metrics.total_decisions += 1;

        match feedback.result {
            FeedbackType::Success => metrics.successful += 1,
            FeedbackType::Failed => metrics.failed += 1,
            FeedbackType::Partial => {}
        }

        let prev_avg = metrics.avg_reward;
        let count = metrics.total_decisions as f32;
        metrics.avg_reward = (prev_avg * (count - 1.0) + feedback.reward) / count;

        self.update_decision_quality(&feedback);
    }

    fn update_decision_quality(&self, feedback: &DecisionFeedback) {
        let mut quality = self.decision_quality.lock();
        let current = quality.entry(feedback.decision).or_insert(0.0);

        let reward_factor = match feedback.result {
            FeedbackType::Success => feedback.reward * 1.2,
            FeedbackType::Partial => feedback.reward * 0.8,
            FeedbackType::Failed => feedback.reward * 0.1,
        };

        *current = (*current * 0.9) + (reward_factor * 0.1);
    }

    pub fn calculate_success_rate(&self) -> f32 {
        let metrics = self.learning_metrics.lock();
        if metrics.total_decisions == 0 {
            return 0.0;
        }
        metrics.successful as f32 / metrics.total_decisions as f32
    }

    pub fn calculate_failure_rate(&self) -> f32 {
        let metrics = self.learning_metrics.lock();
        if metrics.total_decisions == 0 {
            return 0.0;
        }
        metrics.failed as f32 / metrics.total_decisions as f32
    }

    pub fn get_best_decisions(&self, limit: usize) -> Vec<(Decision, f32)> {
        let quality = self.decision_quality.lock();
        let mut decisions: Vec<_> = quality.iter()
            .map(|(&d, &q)| (d, q))
            .collect();

        decisions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        decisions.truncate(limit);
        decisions
    }

    pub fn get_worst_decisions(&self, limit: usize) -> Vec<(Decision, f32)> {
        let quality = self.decision_quality.lock();
        let mut decisions: Vec<_> = quality.iter()
            .map(|(&d, &q)| (d, q))
            .collect();

        decisions.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));
        decisions.truncate(limit);
        decisions
    }

    pub fn adjust_learning_rate(&self, new_rate: f32) {
        let mut lr = self.learning_rate.lock();
        *lr = new_rate.max(0.001).min(0.1);
    }

    pub fn adaptive_learning_rate(&self) {
        let metrics = self.learning_metrics.lock();
        let success_rate = self.calculate_success_rate();

        let lr = if success_rate > 0.8 {
            0.015
        } else if success_rate < 0.3 {
            0.005
        } else {
            0.01
        };

        drop(metrics);
        self.adjust_learning_rate(lr);
    }

    pub fn calculate_learning_progress(&self) -> f32 {
        let history = self.feedback_history.lock();
        if history.len() < 2 {
            return 0.0;
        }

        let recent_window = 10.min(history.len());
        let recent = &history[history.len() - recent_window..];

        let recent_success = recent.iter()
            .filter(|f| matches!(f.result, FeedbackType::Success))
            .count() as f32 / recent_window as f32;

        let old_start = (history.len() / 2).max(10);
        let old_window = 10.min(old_start);
        let old = &history[old_start - old_window..old_start];

        let old_success = old.iter()
            .filter(|f| matches!(f.result, FeedbackType::Success))
            .count() as f32 / old_window as f32;

        (recent_success - old_success).max(0.0)
    }

    pub fn generate_rule_adjustments(&self) -> Vec<RuleAdjustment> {
        let mut adjustments = Vec::new();
        let worst = self.get_worst_decisions(5);
        let lr = self.learning_rate.lock();

        for (decision, quality) in worst.iter() {
            let adjustment = RuleAdjustment {
                rule_id: *decision,
                weight_delta: -(*quality) * *lr,
                confidence_change: -0.05,
            };
            adjustments.push(adjustment);
        }

        adjustments
    }

    pub fn apply_adjustment(&self, rule_id: u32, delta: f32) {
        let mut adjustments = self.rule_adjustments.lock();
        let current = adjustments.entry(rule_id).or_insert(0.0);
        *current += delta;
    }

    pub fn get_feedback_summary(&self) -> (u32, u32, u32, f32) {
        let metrics = self.learning_metrics.lock();
        (
            metrics.total_decisions,
            metrics.successful,
            metrics.failed,
            metrics.avg_reward,
        )
    }

    pub fn get_recent_feedback(&self, limit: usize) -> Vec<DecisionFeedback> {
        let history = self.feedback_history.lock();
        let start = if history.len() > limit {
            history.len() - limit
        } else {
            0
        };
        history[start..].to_vec()
    }

    pub fn identify_problem_modules(&self) -> Vec<(ModuleId, f32)> {
        let history = self.feedback_history.lock();
        let mut module_scores: BTreeMap<ModuleId, (u32, u32)> = BTreeMap::new();

        for feedback in history.iter() {
            let entry = module_scores.entry(feedback.source_module).or_insert((0, 0));
            entry.0 += 1;

            if matches!(feedback.result, FeedbackType::Failed) {
                entry.1 += 1;
            }
        }

        let mut problems: Vec<_> = module_scores.iter()
            .map(|(&module_id, &(total, failed))| {
                let failure_rate = failed as f32 / total.max(1) as f32;
                (module_id, failure_rate)
            })
            .filter(|(_, rate)| *rate > 0.3)
            .collect();

        problems.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        problems
    }

    pub fn reset_metrics(&self) {
        let mut metrics = self.learning_metrics.lock();
        *metrics = LearningMetrics {
            total_decisions: 0,
            successful: 0,
            failed: 0,
            avg_reward: 0.0,
            learning_progress: 0.0,
        };
    }
}
