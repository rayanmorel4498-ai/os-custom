use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use spin::Mutex;
use crate::prelude::String;
use crate::core::ai_orchestrator::{AIOrchestrator, ExecutionContext, ExecutionState};
use crate::core::intelligent_router::IntelligentRouter;
use crate::core::thread_pool::{PoolExecutor, WorkerTask};
use crate::core::task_executor::{TaskRegistry, create_registry};
use crate::core::global_state::GlobalStateManager;
use crate::core::model_cache::{ModelCache, create_default_models};
use crate::modules::reasoning::{Reasoner, Fact};
use crate::modules::self_learning::{SelfLearner, Experience};

#[derive(Clone)]
pub struct TLSIntegrationContext {
    pub ia_component_type: String,
    pub instance_id: u32,
    pub session_token: Option<String>,
    pub token_hash: Option<[u8; 32]>,
    pub token_nonce: u64,
    pub is_authenticated: bool,
    pub min_token_len: usize,
    pub min_secret_len: usize,
    pub last_nonce: u64,
    pub secret_vec: Option<Vec<u8>>,
}

impl TLSIntegrationContext {
    pub fn new() -> Self {
        Self {
            ia_component_type: "IA".into(),
            instance_id: 0,
            session_token: None,
            token_hash: None,
            token_nonce: 0,
            is_authenticated: false,
            min_token_len: 16,
            min_secret_len: 16,
            last_nonce: 0,
            secret_vec: None,
        }
    }

    pub fn set_token_signed(&mut self, token: String, secret: &str, nonce: u64) -> bool {
        if token.len() < self.min_token_len || secret.len() < self.min_secret_len {
            self.clear_auth();
            return false;
        }
        if nonce <= self.last_nonce {
            self.clear_auth();
            return false;
        }
        let hash = Self::sign_token(secret, &token, nonce);
        self.session_token = Some(token);
        self.token_hash = Some(hash);
        self.token_nonce = nonce;
        self.is_authenticated = true;
        self.last_nonce = nonce;
        self.secret_vec = None;
        true
    }

    pub fn set_token_signed_with_secret_vec(&mut self, token: String, secret: Vec<u8>, nonce: u64) -> bool {
        if token.len() < self.min_token_len || secret.len() < self.min_secret_len {
            self.clear_auth();
            return false;
        }
        if nonce <= self.last_nonce {
            self.clear_auth();
            return false;
        }
        let hash = Self::sign_token_bytes(&secret, &token, nonce);
        self.session_token = Some(token);
        self.token_hash = Some(hash);
        self.token_nonce = nonce;
        self.is_authenticated = true;
        self.last_nonce = nonce;
        self.secret_vec = Some(secret);
        true
    }

    pub fn get_token(&self) -> Option<&String> {
        self.session_token.as_ref()
    }

    pub fn verify_token(&self, token: &str, secret: &str) -> bool {
        if token.len() < self.min_token_len || secret.len() < self.min_secret_len {
            return false;
        }
        if let Some(stored) = self.token_hash {
            let computed = Self::sign_token(secret, token, self.token_nonce);
            stored == computed
        } else {
            false
        }
    }

    pub fn verify_token_with_secret_vec(&self, token: &str, secret: &[u8]) -> bool {
        if token.len() < self.min_token_len || secret.len() < self.min_secret_len {
            return false;
        }
        if let Some(stored) = self.token_hash {
            let computed = Self::sign_token_bytes(secret, token, self.token_nonce);
            stored == computed
        } else {
            false
        }
    }

    fn sign_token(secret: &str, token: &str, nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(token.as_bytes());
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result[..]);
        out
    }

    fn sign_token_bytes(secret: &[u8], token: &str, nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(token.as_bytes());
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result[..]);
        out
    }

    pub fn is_valid(&self) -> bool {
        self.is_authenticated
            && self.token_hash.is_some()
            && self.session_token.is_some()
            && self.token_nonce > 0
            && self.last_nonce == self.token_nonce
            && self.session_token.as_ref().map(|t| t.len() >= self.min_token_len).unwrap_or(false)
    }

    fn clear_auth(&mut self) {
        self.session_token = None;
        self.token_hash = None;
        self.token_nonce = 0;
        self.is_authenticated = false;
        self.secret_vec = None;
    }
}

impl Default for TLSIntegrationContext {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TLSIntegrationManager {
    context: Mutex<TLSIntegrationContext>,
    orchestrator: Mutex<AIOrchestrator>,
    router: Mutex<IntelligentRouter>,
    secondary_loop_active: Mutex<bool>,
    execution_queue: Mutex<Vec<ExecutionContext>>,
    pool_executor: Mutex<PoolExecutor>,
    task_registry: Mutex<TaskRegistry>,
    global_state: Mutex<GlobalStateManager>,
    model_cache: Mutex<ModelCache>,
    reasoner: Mutex<Reasoner>,
    self_learner: Mutex<SelfLearner>,
}

impl TLSIntegrationManager {
    pub fn new() -> Self {
        let manager = Self {
            context: Mutex::new(TLSIntegrationContext::new()),
            orchestrator: Mutex::new(AIOrchestrator::new()),
            router: Mutex::new(IntelligentRouter::new()),
            secondary_loop_active: Mutex::new(false),
            execution_queue: Mutex::new(Vec::new()),
            pool_executor: Mutex::new(PoolExecutor::new(8, 10)),
            task_registry: Mutex::new(create_registry()),
            global_state: Mutex::new(GlobalStateManager::new()),
            model_cache: Mutex::new(ModelCache::new(64)),
            reasoner: Mutex::new(Reasoner::new()),
            self_learner: Mutex::new(SelfLearner::new(0.2, 0.95)),
        };

        manager.preload_models();
        manager
    }

    fn preload_models(&self) {
        let models = create_default_models();
        let cache = self.model_cache.lock();

        for model in models {
            let _ = cache.cache_model(model);
        }
    }

    pub fn authenticate(&self, token: String, secret: &str, nonce: u64) -> bool {
        let mut ctx = self.context.lock();
        if !ctx.set_token_signed(token, secret, nonce) {
            return false;
        }
        ctx.is_valid()
    }

    pub fn authenticate_with_secret_vec(&self, token: String, secret: Vec<u8>, nonce: u64) -> bool {
        let mut ctx = self.context.lock();
        if !ctx.set_token_signed_with_secret_vec(token, secret, nonce) {
            return false;
        }
        ctx.is_valid()
    }

    pub fn get_context(&self) -> TLSIntegrationContext {
        self.context.lock().clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.context.lock().is_valid()
    }

    pub fn reset(&self) {
        let mut ctx = self.context.lock();
        *ctx = TLSIntegrationContext::new();
    }

    pub fn start_secondary_loop(&self) {
        let mut active = self.secondary_loop_active.lock();
        *active = true;
    }

    pub fn stop_secondary_loop(&self) {
        let mut active = self.secondary_loop_active.lock();
        *active = false;
    }

    pub fn is_loop_active(&self) -> bool {
        *self.secondary_loop_active.lock()
    }

    pub fn submit_task_to_ai(&self, module_id: u32, data: Vec<u8>, priority: u8) -> u64 {
        let orchestrator = self.orchestrator.lock();
        orchestrator.submit_task(module_id, data, priority)
    }

    pub fn internal_loop_iteration(&self) {
        if !self.is_loop_active() {
            return;
        }

        let orchestrator = self.orchestrator.lock();
        let pending = orchestrator.get_pending_tasks();
        drop(orchestrator);

        let pool_executor = self.pool_executor.lock();

        for context in pending.iter().take(32) {
            let worker_task = WorkerTask {
                context: context.clone(),
                task_fn: None,
            };

            pool_executor.submit(worker_task);
        }

        let executed = pool_executor.run_iteration();
        drop(pool_executor);

        if executed > 0 {
            let orchestrator = self.orchestrator.lock();
            for context in pending.iter().take(executed as usize) {
                orchestrator.update_context_state(context.id, ExecutionState::Completed);
            }
        }

        self.check_and_adapt();
    }

    fn execute_task_in_tls(&self, context: &ExecutionContext, _target_module: u32) {
        let registry = self.task_registry.lock();
        let result = registry.execute_task(context.module_id % 9, context);
        drop(registry);

        let reasoning_score = self.apply_reasoning(context);
        self.apply_self_learning(context, result, reasoning_score);

        let orchestrator = self.orchestrator.lock();
        orchestrator.update_context_state(context.id, ExecutionState::Completed);
        orchestrator.record_decision(context.module_id, result, if result == 0 { 0.9 } else { 0.3 });
    }

    fn apply_reasoning(&self, context: &ExecutionContext) -> f32 {
        let mut reasoner = self.reasoner.lock();
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

    fn apply_self_learning(&self, context: &ExecutionContext, result: u32, reasoning_score: f32) {
        let mut learner = self.self_learner.lock();
        let state = Self::build_state_vector(&context.data, 32);
        let next_state = Self::build_next_state_vector(&context.data, 32);
        let action = if !context.data.is_empty() { (context.data[0] as u32) % 8 } else { 0 };
        let reward = if result == 0 { 1.0 } else { 0.0 } + reasoning_score * 0.5;

        let experience = Experience::new(state, action, reward, next_state);
        learner.learn(experience);
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

    fn check_and_adapt(&self) {
        let router = self.router.lock();
        let (success, _failure, _progress) = router.get_system_health();
        drop(router);

        if success < 0.7 {
            let router = self.router.lock();
            router.adapt_system();
        }
    }

    pub fn get_pool_status(&self) -> (u32, u32, u32) {
        let pool_executor = self.pool_executor.lock();
        pool_executor.get_status()
    }

    pub fn get_task_stats(&self) -> Vec<(u32, u32, u32)> {
        let registry = self.task_registry.lock();
        registry.get_all_stats()
    }

    pub fn snapshot_state(&self) {
        let global_state = self.global_state.lock();
        global_state.snapshot();
    }

    pub fn get_ai_health(&self) -> (u32, u32, f32, f32) {
        let global_state = self.global_state.lock();
        let (active, total) = global_state.get_module_health();
        let cache_ratio = global_state.get_cache_ratio();

        let state = global_state.get_state();
        let avg_confidence = if state.decisions_history.is_empty() {
            0.0
        } else {
            state.decisions_history.iter().map(|(_, c)| c).sum::<f32>() / state.decisions_history.len() as f32
        };

        (active, total, cache_ratio, avg_confidence)
    }

    pub fn get_model_stats(&self) -> (u32, u32, f32) {
        let cache = self.model_cache.lock();
        cache.get_cache_stats()
    }

    pub fn run_tls_secondary_loop(&self) {
        self.start_secondary_loop();

        while self.is_loop_active() {
            self.internal_loop_iteration();
            self.snapshot_state();
        }
    }
}

impl Default for TLSIntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tls_authentication() {
        let manager = TLSIntegrationManager::new();
        assert!(!manager.is_authenticated());

        let token = "test_token_123456";
        let secret = "secret_key_123456";
        let _ = manager.authenticate(token.into(), secret, 42);
        assert!(manager.is_authenticated());

        let ctx = manager.get_context();
        assert_eq!(ctx.get_token().map(|s| s.as_str()), Some(token));
        assert!(ctx.verify_token(token, secret));
    }

    #[tokio::test]
    async fn test_tls_reset() {
        let manager = TLSIntegrationManager::new();
        let token = "token_1234567890";
        let secret = "secret_key_123456";
        let _ = manager.authenticate(token.into(), secret, 7);
        assert!(manager.is_authenticated());

        manager.reset();
        assert!(!manager.is_authenticated());
    }
}
