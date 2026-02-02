use alloc::vec::Vec;
use crate::prelude::String;
use spin::Mutex;
use crate::core::ai_orchestrator::{AIOrchestrator, ExecutionContext};
use crate::modules::reasoning::{Reasoner, Fact};
use crate::modules::self_learning::{SelfLearner, Experience};
use crate::modules::deep_learning::{DeepLearner, ConvLayer, DenseLayer, Activation};
use crate::ml::{FaceModel, VoiceModel, FingerprintModel};
use crate::r#loop::pipeline_executor::PipelineExecutor;
use crate::r#loop::loop_manager::LoopState;
use crate::core::init::{
    with_adaptive_scheduler,
    with_explainability_mut,
    with_local_profiler,
    with_long_term_memory_mut,
    with_low_power_ai,
    with_policy_engine,
    with_resource_quota,
    with_resource_quota_mut,
    with_timekeeper,
    with_user_rules,
};
use crate::core::resource_quota::{AdmissionDecision, PriorityClass};
use crate::core::policy_engine::PolicyDecision;

const CMD_ENROLL_FACE: u8 = 0xE1;
const CMD_VERIFY_FACE: u8 = 0xE2;
const CMD_ENROLL_VOICE: u8 = 0xE3;
const CMD_VERIFY_VOICE: u8 = 0xE4;
const CMD_ENROLL_FINGERPRINT: u8 = 0xE5;
const CMD_VERIFY_FINGERPRINT: u8 = 0xE6;
const MAX_TEMPLATES: usize = 8;

pub struct SecondaryLoop {
    state: Mutex<LoopState>,
    reasoner: Mutex<Reasoner>,
    self_learner: Mutex<SelfLearner>,
    deep_learner: Mutex<DeepLearner>,
    diagnostics: Mutex<LoopDiagnostics>,
    face_model: FaceModel,
    voice_model: VoiceModel,
    fingerprint_model: FingerprintModel,
    biometric_cache: Mutex<BiometricCache>,
}

impl SecondaryLoop {
    pub fn new() -> Self {
        SecondaryLoop {
            state: Mutex::new(LoopState::new()),
            reasoner: Mutex::new(Reasoner::new()),
            self_learner: Mutex::new(SelfLearner::new(0.2, 0.95)),
            deep_learner: Mutex::new(DeepLearner::new()),
            diagnostics: Mutex::new(LoopDiagnostics::new()),
            face_model: FaceModel::new(),
            voice_model: VoiceModel::new(),
            fingerprint_model: FingerprintModel::new(),
            biometric_cache: Mutex::new(BiometricCache::new()),
        }
    }

    pub fn run(&self, timestamp_ms: u64, orchestrator: &AIOrchestrator, pipeline: &PipelineExecutor) {
        let mut state = self.state.lock();
        if !state.enabled {
            return;
        }

        if self.should_pause_ai(timestamp_ms) {
            state.iterations += 1;
            state.last_tick_ms = timestamp_ms;
            return;
        }

        let pending = orchestrator.get_pending_tasks();
        let max_tasks = if self.is_over_budget() { 4 } else { 12 };
        let mut processed = 0u32;
        for ctx in pending.iter().take(max_tasks) {
            let admission = self.is_over_module_quota(ctx);
            if admission == AdmissionDecision::Drop {
                processed += 1;
                continue;
            }
            if self.is_blocked_by_policy(ctx, timestamp_ms) {
                processed += 1;
                continue;
            }
            if admission == AdmissionDecision::Throttle {
                let reasoning_score = self.apply_reasoning(ctx);
                self.record_explainability(ctx, None, reasoning_score, timestamp_ms);
                processed += 1;
                continue;
            }
            let mut decision_conf = None;
            if let Some((decision, confidence)) = self.process_biometric(ctx, pipeline) {
                decision_conf = Some((decision, confidence));
                orchestrator.record_decision(ctx.module_id, decision, confidence);
            }
            let reasoning_score = self.apply_reasoning(ctx);
            self.apply_self_learning(ctx, reasoning_score);
            self.apply_deep_learning(ctx, decision_conf, reasoning_score);
            self.record_long_term_memory(ctx, reasoning_score, decision_conf);
            self.record_explainability(ctx, decision_conf, reasoning_score, timestamp_ms);
            processed += 1;
        }

        state.iterations += 1;
        state.last_tick_ms = timestamp_ms;
        state.processed += processed;
    }

    fn apply_reasoning(&self, context: &ExecutionContext) -> f32 {
        let mut reasoner = self.reasoner.lock();
        reasoner.reset();
        let facts = self.build_facts_from_data(&context.data);
        for fact in facts {
            reasoner.add_fact(fact);
        }

        let avg = Self::average_byte(&context.data);
        if avg > 0.5 {
            reasoner.add_rule("avg:gt:0.5".into(), "data_high".into());
        } else {
            reasoner.add_rule("avg:le:0.5".into(), "data_low".into());
        }

        let conclusions = reasoner.infer();
        if conclusions.is_empty() {
            0.0
        } else {
            (conclusions.len() as f32 / 4.0).min(1.0)
        }
    }

    fn apply_self_learning(&self, context: &ExecutionContext, reasoning_score: f32) {
        let mut learner = self.self_learner.lock();
        let state = Self::build_state_vector(&context.data, 32);
        let next_state = Self::build_next_state_vector(&context.data, 32);
        let action = if !context.data.is_empty() { (context.data[0] as u32) % 8 } else { 0 };
        let reward = reasoning_score * 0.5;

        let experience = Experience::new(state, action, reward, next_state);
        learner.learn(experience);
        learner.apply_feedback(reward, reward > 0.25);
    }

    fn apply_deep_learning(
        &self,
        context: &ExecutionContext,
        decision_conf: Option<(u32, f32)>,
        reasoning_score: f32,
    ) {
        if self.is_low_power_only() || self.is_over_budget() {
            return;
        }
        if !self.diagnostics.lock().deep_learning_enabled {
            return;
        }
        let input = Self::build_state_vector(&context.data, 48);
        if input.is_empty() {
            return;
        }

        let mut learner = self.deep_learner.lock();
        self.ensure_deep_learner_setup(&mut learner, input.len());

        let reward = match decision_conf {
            Some((decision, conf)) => {
                let margin = (conf - 0.5) * 2.0;
                let sign = if decision == 1 { 1.0 } else { -1.0 };
                let base = sign * margin;
                let combined = base + reasoning_score * 0.4;
                Self::amplify_and_clamp(combined, 0.9, 0.01)
            }
            None => Self::amplify_and_clamp(reasoning_score * 0.4, 0.9, 0.01),
        };

        let loss = learner.train_with_feedback(&input, reward, 0.01);
        self.update_diagnostics(&input, reward, loss);
    }

    fn amplify_and_clamp(value: f32, gain: f32, min_abs: f32) -> f32 {
        let scaled = value * gain;
        let soft = scaled / (1.0 + scaled.abs());
        let mut v = (0.7 * soft) + (0.3 * scaled);
        v = v.clamp(-1.0, 1.0);
        if v.abs() < min_abs {
            v = if v >= 0.0 { min_abs } else { -min_abs };
        }
        v
    }

    fn ensure_deep_learner_setup(&self, learner: &mut DeepLearner, input_size: usize) {
        if learner.is_configured() {
            return;
        }

        learner.add_conv_layer(ConvLayer::new(4));
        let dense_in = ((input_size + 3) / 4).max(1);
        learner.add_dense_layer(DenseLayer::new(dense_in, 16, Activation::Relu));
        learner.add_dense_layer(DenseLayer::new(16, 4, Activation::Linear));
    }

    fn process_biometric(&self, context: &ExecutionContext, pipeline: &PipelineExecutor) -> Option<(u32, f32)> {
        let cmd = *context.data.first()?;
        let payload = if context.data.len() > 1 { &context.data[1..] } else { &[] };
        if payload.is_empty() {
            return None;
        }

        let mut cache = self.biometric_cache.lock();

        let (is_enroll, confidence) = match cmd {
            CMD_ENROLL_FACE => {
                cache.enroll_face(payload);
                (true, 1.0)
            }
            CMD_VERIFY_FACE => {
                let conf = cache.verify_face(payload, &self.face_model);
                (false, conf)
            }
            CMD_ENROLL_VOICE => {
                cache.enroll_voice(payload);
                (true, 1.0)
            }
            CMD_VERIFY_VOICE => {
                let conf = cache.verify_voice(payload, &self.voice_model);
                (false, conf)
            }
            CMD_ENROLL_FINGERPRINT => {
                cache.enroll_fingerprint(payload);
                (true, 1.0)
            }
            CMD_VERIFY_FINGERPRINT => {
                let conf = cache.verify_fingerprint(payload, &self.fingerprint_model);
                (false, conf)
            }
            _ => return None,
        };

        let task_id = pipeline.create_pipeline(context.id);
        let _ = pipeline.progress_task(task_id, 0);

        let decision = if is_enroll { 1 } else { if confidence >= 0.75 { 1 } else { 0 } };
        Some((decision, confidence))
    }

    fn should_pause_ai(&self, timestamp_ms: u64) -> bool {
        let hour = with_timekeeper(|tk| tk.hour_24()).unwrap_or(((timestamp_ms / 3_600_000) % 24) as u8);
        with_user_rules(|rules| rules.should_silence(hour, None)).unwrap_or(false)
    }

    fn is_low_power_only(&self) -> bool {
        with_low_power_ai(|mode| mode.should_use_light_model()).unwrap_or(false)
    }

    fn is_over_budget(&self) -> bool {
        let usage = with_local_profiler(|profiler| profiler.snapshot()).unwrap_or_default();
        with_adaptive_scheduler(|sched| sched.is_over_budget(&usage)).unwrap_or(false)
    }

    fn is_over_module_quota(&self, context: &ExecutionContext) -> AdmissionDecision {
        let module_key = alloc::format!("module:{}", context.module_id);
        let now_ms = with_timekeeper(|tk| tk.now_ms()).unwrap_or(0);
        let cpu_ms = Self::estimate_cpu_cost(context);
        let decision = with_resource_quota_mut(|quota| {
            quota.record_cpu(&module_key, cpu_ms, now_ms);
            quota.record_latency(&module_key, cpu_ms);
            quota.admission_decision(&module_key, Self::priority_class(context.priority))
        }).unwrap_or(AdmissionDecision::Allow);
        if decision != AdmissionDecision::Allow {
            return decision;
        }
        let usage = with_local_profiler(|profiler| profiler.get_usage(&module_key)).unwrap_or(None);
        if usage.is_some() {
            with_resource_quota(|quota| quota.admission_decision(&module_key, Self::priority_class(context.priority)))
                .unwrap_or(AdmissionDecision::Allow)
        } else {
            AdmissionDecision::Allow
        }
    }

    fn priority_class(priority: u8) -> PriorityClass {
        if priority >= 200 { PriorityClass::Realtime } else { PriorityClass::BestEffort }
    }

    fn estimate_cpu_cost(context: &ExecutionContext) -> u64 {
        let len = context.data.len() as u64;
        (len / 256).saturating_add(1)
    }

    fn is_blocked_by_policy(&self, context: &ExecutionContext, timestamp_ms: u64) -> bool {
        let key = alloc::format!("module:{}", context.module_id);
        let decision = with_policy_engine(|engine| engine.decide(&key)).unwrap_or(PolicyDecision::Allow);
        match decision {
            PolicyDecision::Allow => false,
            PolicyDecision::RequireConsent | PolicyDecision::Deny => {
                self.record_policy_block(&key, timestamp_ms, decision);
                true
            }
        }
    }

    fn record_policy_block(&self, key: &str, timestamp_ms: u64, decision: PolicyDecision) {
        let rule = match decision {
            PolicyDecision::RequireConsent => "policy:consent",
            PolicyDecision::Deny => "policy:deny",
            PolicyDecision::Allow => "policy:allow",
        };
        let _ = with_explainability_mut(|store| {
            store.record_with_details(
                key,
                "blocked_by_policy",
                alloc::vec!["policy_block".into()],
                alloc::vec![rule.into()],
                alloc::vec![("policy".into(), 1.0)],
                timestamp_ms,
            );
        });
    }

    fn record_long_term_memory(
        &self,
        context: &ExecutionContext,
        reasoning_score: f32,
        decision_conf: Option<(u32, f32)>,
    ) {
        let key = alloc::format!("module:{}", context.module_id);
        let value = alloc::format!("reasoning={:.2},decision={:?}", reasoning_score, decision_conf);
        let _ = with_long_term_memory_mut(|mem| {
            mem.set_habit(&key, &value, 0, reasoning_score.clamp(0.0, 1.0));
        });
    }

    fn record_explainability(
        &self,
        context: &ExecutionContext,
        decision_conf: Option<(u32, f32)>,
        reasoning_score: f32,
        timestamp_ms: u64,
    ) {
        let id = alloc::format!("decision:{}", context.id);
        let mut weights = alloc::vec![("reasoning".into(), reasoning_score)];
        if let Some((_, conf)) = decision_conf {
            weights.push(("confidence".into(), conf));
        }
        let rules = alloc::vec!["reasoning".into()];
        let factors = alloc::vec![alloc::format!("data_len={}", context.data.len())];
        let _ = with_explainability_mut(|store| {
            store.record_with_details(&id, "decision", factors, rules, weights, timestamp_ms);
        });
    }

    fn build_facts_from_data(&self, data: &[u8]) -> Vec<Fact> {
        let mut facts = Vec::new();
        for (i, byte) in data.iter().take(16).enumerate() {
            let subject = alloc::format!("byte_{}", i);
            let predicate = "value".into();
            let object = alloc::format!("{}", byte);
            facts.push(Fact::new(subject, predicate, object));
        }
        facts
    }

    fn build_state_vector(data: &[u8], max_len: usize) -> Vec<f32> {
        let mut state = Vec::new();
        for &b in data.iter().take(max_len) {
            state.push(b as f32 / 255.0);
        }
        if state.is_empty() {
            state.push(0.0);
        }
        state
    }

    fn build_next_state_vector(data: &[u8], max_len: usize) -> Vec<f32> {
        let mut next_state = Vec::new();
        for &b in data.iter().rev().take(max_len) {
            next_state.push(b as f32 / 255.0);
        }
        if next_state.is_empty() {
            next_state.push(0.0);
        }
        next_state
    }

    fn average_byte(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        (sum as f32 / data.len() as f32) / 255.0
    }

    pub fn get_state(&self) -> LoopState {
        *self.state.lock()
    }

    pub fn get_diagnostics(&self) -> LoopDiagnostics {
        *self.diagnostics.lock()
    }

    pub fn export_diagnostics(&self) -> String {
        self.diagnostics.lock().export()
    }

    fn update_diagnostics(&self, input: &[f32], reward: f32, loss: f32) {
        let mut diag = self.diagnostics.lock();
        let (mean, var) = Self::mean_var(input);

        let drift = (mean - diag.input_mean_ema).abs() + (var - diag.input_var_ema).abs();

        let prev_loss_ema = diag.loss_ema;
        let alpha = diag.ema_alpha;
        diag.reward_ema = alpha * reward + (1.0 - alpha) * diag.reward_ema;
        diag.loss_ema = alpha * loss + (1.0 - alpha) * diag.loss_ema;
        diag.input_mean_ema = alpha * mean + (1.0 - alpha) * diag.input_mean_ema;
        diag.input_var_ema = alpha * var + (1.0 - alpha) * diag.input_var_ema;

        let loss_increase = (diag.loss_ema - prev_loss_ema).max(0.0);
        diag.overfit_score = loss_increase * diag.reward_ema.abs();
        diag.drift_score = drift;
        diag.last_reward = reward;
        diag.last_loss = loss;

        diag.alert_overfit = diag.overfit_score > diag.overfit_threshold;
        diag.alert_drift = diag.drift_score > diag.drift_threshold;

        if diag.ab_gating_enabled {
            if diag.alert_overfit || diag.alert_drift {
                diag.cooldown_ticks = diag.cooldown_max;
                diag.deep_learning_enabled = false;
            } else if diag.cooldown_ticks > 0 {
                diag.cooldown_ticks -= 1;
                diag.deep_learning_enabled = false;
            } else {
                diag.deep_learning_enabled = true;
            }
        }
    }

    fn mean_var(input: &[f32]) -> (f32, f32) {
        if input.is_empty() {
            return (0.0, 0.0);
        }
        let mut sum = 0.0f32;
        for &v in input {
            sum += v;
        }
        let mean = sum / input.len() as f32;
        let mut var_sum = 0.0f32;
        for &v in input {
            let d = v - mean;
            var_sum += d * d;
        }
        let var = var_sum / input.len() as f32;
        (mean, var)
    }
}

#[derive(Clone, Copy)]
pub struct LoopDiagnostics {
    pub reward_ema: f32,
    pub loss_ema: f32,
    pub input_mean_ema: f32,
    pub input_var_ema: f32,
    pub drift_score: f32,
    pub overfit_score: f32,
    pub last_reward: f32,
    pub last_loss: f32,
    pub ema_alpha: f32,
    pub drift_threshold: f32,
    pub overfit_threshold: f32,
    pub alert_drift: bool,
    pub alert_overfit: bool,
    pub ab_gating_enabled: bool,
    pub deep_learning_enabled: bool,
    pub cooldown_ticks: u32,
    pub cooldown_max: u32,
}

impl LoopDiagnostics {
    pub fn new() -> Self {
        LoopDiagnostics {
            reward_ema: 0.0,
            loss_ema: 0.0,
            input_mean_ema: 0.0,
            input_var_ema: 0.0,
            drift_score: 0.0,
            overfit_score: 0.0,
            last_reward: 0.0,
            last_loss: 0.0,
            ema_alpha: 0.1,
            drift_threshold: 0.25,
            overfit_threshold: 0.15,
            alert_drift: false,
            alert_overfit: false,
            ab_gating_enabled: true,
            deep_learning_enabled: true,
            cooldown_ticks: 0,
            cooldown_max: 10,
        }
    }

    pub fn export(&self) -> String {
        alloc::format!(
            "reward_ema={:.4}, loss_ema={:.4}, drift={:.4}, overfit={:.4}, alert_drift={}, alert_overfit={}, dl_enabled={}, cooldown={}",
            self.reward_ema,
            self.loss_ema,
            self.drift_score,
            self.overfit_score,
            self.alert_drift,
            self.alert_overfit,
            self.deep_learning_enabled,
            self.cooldown_ticks
        )
    }
}

struct BiometricCache {
    face_templates: Vec<Vec<u8>>,
    voice_templates: Vec<Vec<u8>>,
    fingerprint_templates: Vec<Vec<u8>>,
}

impl BiometricCache {
    fn new() -> Self {
        BiometricCache {
            face_templates: Vec::new(),
            voice_templates: Vec::new(),
            fingerprint_templates: Vec::new(),
        }
    }

    fn enroll_face(&mut self, data: &[u8]) {
        Self::push_template(&mut self.face_templates, data);
    }

    fn enroll_voice(&mut self, data: &[u8]) {
        Self::push_template(&mut self.voice_templates, data);
    }

    fn enroll_fingerprint(&mut self, data: &[u8]) {
        Self::push_template(&mut self.fingerprint_templates, data);
    }

    fn verify_face(&self, data: &[u8], model: &FaceModel) -> f32 {
        self.best_similarity(data, &self.face_templates, |a, b| model.similarity(a, b))
    }

    fn verify_voice(&self, data: &[u8], model: &VoiceModel) -> f32 {
        self.best_similarity(data, &self.voice_templates, |a, b| model.similarity(a, b))
    }

    fn verify_fingerprint(&self, data: &[u8], model: &FingerprintModel) -> f32 {
        self.best_similarity(data, &self.fingerprint_templates, |a, b| model.similarity(a, b))
    }

    fn push_template(list: &mut Vec<Vec<u8>>, data: &[u8]) {
        if list.len() >= MAX_TEMPLATES {
            list.remove(0);
        }
        list.push(data.to_vec());
    }

    fn best_similarity<F>(&self, data: &[u8], list: &[Vec<u8>], mut f: F) -> f32
    where
        F: FnMut(&[u8], &[u8]) -> f32,
    {
        let mut best = 0.0f32;
        for tpl in list.iter() {
            let sim = f(data, tpl);
            if sim > best {
                best = sim;
            }
        }
        best
    }
}

impl Default for SecondaryLoop {
    fn default() -> Self {
        Self::new()
    }
}
