use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use sha2::{Digest, Sha256};
use spin::Mutex;
use crate::prelude::String;
use crate::security::tls::bundle as tls_bundle;
use crate::time;
use crate::utils::error::ErrorCode;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::core::ai_orchestrator::{AIOrchestrator, ExecutionContext, ExecutionState};
use crate::core::intelligent_router::IntelligentRouter;
use crate::core::thread_pool::{PoolExecutor, WorkerTask};
use crate::core::task_executor::{TaskRegistry, create_registry};
use crate::core::global_state::GlobalStateManager;
use crate::core::model_cache::{ModelCache, create_default_models};
use crate::modules::reasoning::reasoning::{Fact, Reasoner};
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
    pub ia_id: Option<u64>,
    pub pool_id: Option<u32>,
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
            ia_id: None,
            pool_id: None,
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
        self.ia_id = None;
        self.pool_id = None;
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
    ephemeral_handles: Mutex<BTreeMap<String, u64>>,
}

const EPH_TTL_MS: u64 = 30_000;
const DEFAULT_CAPTURE_LEN: usize = 256;
static EPH_COUNTER: AtomicU64 = AtomicU64::new(1);

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
            ephemeral_handles: Mutex::new(BTreeMap::new()),
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

    pub fn secret_for_component(&self, component: &str) -> Option<Vec<u8>> {
        let _ = component;
        self.context.lock().secret_vec.clone()
    }

    pub fn set_pool_id(&self, pool_id: u32) {
        self.context.lock().pool_id = Some(pool_id);
    }

    pub fn set_ia_id(&self, ia_id: u64) {
        self.context.lock().ia_id = Some(ia_id);
    }

    pub fn pool_id(&self) -> Option<u32> {
        self.context.lock().pool_id
    }

    pub fn ia_id(&self) -> Option<u64> {
        self.context.lock().ia_id
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

    pub fn handle_tls_request(&self, payload: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        let now_ms = time::now_ms();
        let text = core::str::from_utf8(payload).map_err(|_| ErrorCode::ErrProtocol)?;
        if text.starts_with("AI_BOOT_REQ") {
            return self.handle_boot_request(text);
        }
        if text.starts_with("EPH_REQ") {
            return self.handle_eph_request(text, now_ms);
        }
        if text.starts_with("CAP_REQ") {
            return self.handle_cap_request(text, now_ms);
        }
        Err(ErrorCode::ErrInvalidInput)
    }

    fn handle_boot_request(&self, text: &str) -> Result<Vec<u8>, ErrorCode> {
        let mut nonce_hex = String::new();
        let mut signature = String::new();
        let mut version = 0u32;
        let mut op = String::new();
        let mut mode = String::new();
        let mut first_run = String::new();
        for part in text.split(';') {
            if part.is_empty() {
                continue;
            }
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            match key {
                "AI_BOOT_REQ" => {}
                "v" => version = value.parse::<u32>().unwrap_or(0),
                "op" => op = value.to_string(),
                "mode" => mode = value.to_string(),
                "first_run" => first_run = value.to_string(),
                "nonce" => nonce_hex = value.to_string(),
                "sig" => signature = value.to_string(),
                _ => {}
            }
        }
        if version != 1 || op != "BOOT" || mode != "run" || first_run != "1" || nonce_hex.is_empty() || signature.is_empty() {
            return Err(ErrorCode::ErrInvalidInput);
        }
        let nonce = parse_hex_u64(&nonce_hex).unwrap_or(0);
        if nonce == 0 {
            return Err(ErrorCode::ErrInvalidInput);
        }
        let secret = tls_bundle::client()
            .and_then(|client| client.secret_for_component("ia"))
            .ok_or(ErrorCode::ErrUnauthorized)?;
        if !verify_boot_request_sig(&secret, &nonce_hex, &signature) {
            return Err(ErrorCode::ErrUnauthorized);
        }
        let ia_id = {
            let mut ctx = self.context.lock();
            if ctx.ia_id.is_none() {
                ctx.ia_id = Some(nonce);
            }
            ctx.ia_id.unwrap_or(nonce)
        };
        let secret_hex = secret_hex32(&secret);
        Ok(self.boot_ok(&secret, ia_id, &secret_hex))
    }

    fn handle_eph_request(&self, text: &str, now_ms: u64) -> Result<Vec<u8>, ErrorCode> {
        let mut nonce_hex = String::new();
        let mut signature = String::new();
        let mut version = 0u32;
        let mut op = String::new();
        let mut ia_id_hex = String::new();
        let mut pool_id_hex = String::new();
        for part in text.split(';') {
            if part.is_empty() {
                continue;
            }
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            match key {
                "EPH_REQ" => {}
                "v" => version = value.parse::<u32>().unwrap_or(0),
                "op" => op = value.to_string(),
                "ia_id" => ia_id_hex = value.to_string(),
                "pool_id" => pool_id_hex = value.to_string(),
                "nonce" => nonce_hex = value.to_string(),
                "sig" => signature = value.to_string(),
                _ => {}
            }
        }
        if version != 1 || op.is_empty() || ia_id_hex.is_empty() || pool_id_hex.is_empty() || nonce_hex.is_empty() || signature.is_empty() {
            return Ok(self.eph_error("bad_request"));
        }
        let ia_id = parse_hex_u64(&ia_id_hex).unwrap_or(0);
        let pool_id = parse_hex_u32(&pool_id_hex).unwrap_or(0);
        let nonce = parse_hex_u64(&nonce_hex).unwrap_or(0);
        if ia_id == 0 || pool_id == 0 || nonce == 0 {
            return Ok(self.eph_error("bad_request"));
        }
        let secret = tls_bundle::client()
            .and_then(|client| client.secret_for_component("ia"))
            .ok_or(ErrorCode::ErrUnauthorized)?;
        if !verify_eph_request_sig(&secret, &op, ia_id, pool_id, nonce, &signature) {
            return Ok(self.eph_error("bad_signature"));
        }
        let handle = hex_u64_16(EPH_COUNTER.fetch_add(1, Ordering::Relaxed));
        let exp = now_ms.saturating_add(EPH_TTL_MS);
        self.ephemeral_handles.lock().insert(handle.clone(), exp);
        Ok(self.eph_ok(&handle))
    }

    fn handle_cap_request(&self, text: &str, now_ms: u64) -> Result<Vec<u8>, ErrorCode> {
        let mut nonce_hex = String::new();
        let mut op = String::new();
        let mut bundle_b64 = String::new();
        let mut handle = String::new();
        let mut signature = String::new();
        let mut version = 0u32;
        let mut ia_id_hex = String::new();
        let mut pool_id_hex = String::new();
        let mut len: Option<u32> = None;
        for part in text.split(';') {
            if part.is_empty() {
                continue;
            }
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            match key {
                "CAP_REQ" => {}
                "v" => version = value.parse::<u32>().unwrap_or(0),
                "op" => op = value.to_string(),
                "nonce" => nonce_hex = value.to_string(),
                "len" => len = value.parse::<u32>().ok(),
                "bundle" => bundle_b64 = value.to_string(),
                "handle" => handle = value.to_string(),
                "sig" => signature = value.to_string(),
                "ia_id" => ia_id_hex = value.to_string(),
                "pool_id" => pool_id_hex = value.to_string(),
                _ => {}
            }
        }
        if version != 1 || op.is_empty() || bundle_b64.is_empty() || handle.is_empty() || signature.is_empty() || ia_id_hex.is_empty() || pool_id_hex.is_empty() || nonce_hex.is_empty() {
            return Ok(self.cap_error("bad_request"));
        }
        let ia_id = parse_hex_u64(&ia_id_hex).unwrap_or(0);
        let pool_id = parse_hex_u32(&pool_id_hex).unwrap_or(0);
        let nonce = parse_hex_u64(&nonce_hex).unwrap_or(0);
        if ia_id == 0 || pool_id == 0 || nonce == 0 {
            return Ok(self.cap_error("bad_request"));
        }
        let secret = tls_bundle::client()
            .and_then(|client| client.secret_for_component("ia"))
            .ok_or(ErrorCode::ErrUnauthorized)?;
        if !verify_cap_request_sig(&secret, &op, ia_id, pool_id, nonce, &bundle_b64, &handle, &signature) {
            return Ok(self.cap_error("bad_signature"));
        }
        if base64_decode_no_pad(&bundle_b64).is_none() {
            return Ok(self.cap_error("bad_bundle"));
        }
        let mut handles = self.ephemeral_handles.lock();
        let Some(exp) = handles.get(&handle).copied() else {
            return Ok(self.cap_error("invalid_handle"));
        };
        if exp <= now_ms {
            handles.remove(&handle);
            return Ok(self.cap_error("expired_handle"));
        }
        handles.remove(&handle);
        drop(handles);

        let payload_len = len.map(|v| v as usize).unwrap_or(DEFAULT_CAPTURE_LEN);
        let payload = generate_capture_payload(&op, payload_len, nonce);
        let capture_secret = tls_bundle::client()
            .and_then(|client| client.secret_for_component("capture_module"))
            .ok_or(ErrorCode::ErrUnauthorized)?;
        let cap_resp = build_cap_resp_ok(&capture_secret, nonce, &payload);
        let resp_b64 = base64_encode_no_pad(cap_resp.as_bytes());
        Ok(self.cap_ok(&resp_b64))
    }

    fn eph_ok(&self, handle: &str) -> Vec<u8> {
        let sig = sign_eph_ok(handle);
        format!("EPH_OK;v=1;handle={};sig={}", handle, sig).into_bytes()
    }

    fn eph_error(&self, code: &str) -> Vec<u8> {
        let sig = sign_eph_err(code);
        format!("EPH_ERR;v=1;code={};sig={}", code, sig).into_bytes()
    }

    fn cap_ok(&self, resp_b64: &str) -> Vec<u8> {
        let sig = sign_cap_ok(resp_b64);
        format!("CAP_OK;v=1;resp={};sig={}", resp_b64, sig).into_bytes()
    }

    fn cap_error(&self, code: &str) -> Vec<u8> {
        let sig = sign_cap_err(code);
        format!("CAP_ERR;v=1;code={};sig={}", code, sig).into_bytes()
    }

    fn boot_ok(&self, secret: &[u8], ia_id: u64, secret_hex: &str) -> Vec<u8> {
        let sig = sign_boot_ok(secret, ia_id, secret_hex);
        format!(
            "AI_BOOT_OK;v=1;ia_id={};secret={};sig={}",
            hex_u64(ia_id),
            secret_hex,
            sig
        )
        .into_bytes()
    }

    pub fn internal_loop_iteration(&self) {
        if !self.is_loop_active() {
            return;
        }

        let orchestrator = self.orchestrator.lock();
        let pending = orchestrator.get_pending_tasks();
        drop(orchestrator);

        let pool_executor = self.pool_executor.lock();
        let mut failed_submits: Vec<u64> = Vec::new();

        for context in pending.iter().take(32) {
            let worker_task = WorkerTask {
                context: context.clone(),
                handler: noop_task,
                priority: crate::core::thread_pool::TaskPriority::Normal,
                max_runtime_ms: 10,
            };

            if pool_executor.submit(worker_task).is_err() {
                failed_submits.push(context.id);
            }
        }

        let executed = pool_executor.run_iteration();
        drop(pool_executor);

        if executed > 0 {
            let orchestrator = self.orchestrator.lock();
            for context in pending.iter().take(executed as usize) {
                orchestrator.update_context_state(context.id, ExecutionState::Completed);
            }
        }
        if !failed_submits.is_empty() {
            let orchestrator = self.orchestrator.lock();
            for id in failed_submits {
                orchestrator.update_context_state(id, ExecutionState::Failed);
            }
        }

        self.check_and_adapt();
    }

    fn execute_task_in_tls(&self, context: &ExecutionContext, _target_module: u32) {
        let registry = self.task_registry.lock();
        let result = registry.execute_task(context.module_id % 9, context, 0, 0);
        drop(registry);

        let task_result = result.unwrap_or(1);
        let reasoning_score = self.apply_reasoning(context);
        self.apply_self_learning(context, task_result, reasoning_score);

        let orchestrator = self.orchestrator.lock();
        orchestrator.update_context_state(context.id, ExecutionState::Completed);
        orchestrator.record_decision(
            context.module_id,
            task_result,
            if task_result == 0 { 0.9 } else { 0.3 },
        );
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

    pub fn get_pool_status(&self) -> crate::core::thread_pool::PoolMetrics {
        let pool_executor = self.pool_executor.lock();
        pool_executor.get_status()
    }

    pub fn get_task_stats(&self) -> Vec<(crate::core::task_executor::TaskType, crate::core::task_executor::TaskStats)> {
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

fn verify_eph_request_sig(secret: &[u8], op: &str, ia_id: u64, pool_id: u32, nonce: u64, signature: &str) -> bool {
    let base = format!(
        "EPH_REQ;v=1;api=capture;op={};mode=run;first_run=1;ia_id={};pool_id={};nonce={}",
        op,
        hex_u64(ia_id),
        hex_u32(pool_id),
        hex_u64(nonce)
    );
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(base.as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice()) == signature
}

fn sign_eph_ok(handle: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("EPH_OK;v=1;handle={}", handle).as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn sign_eph_err(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("EPH_ERR;v=1;code={}", code).as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn verify_cap_request_sig(
    secret: &[u8],
    op: &str,
    ia_id: u64,
    pool_id: u32,
    nonce: u64,
    bundle_b64: &str,
    handle: &str,
    signature: &str,
) -> bool {
    let base = format!(
        "CAP_REQ;v=1;api=capture;op={};mode=run;first_run=1;ia_id={};pool_id={};handle={};bundle={};nonce={}",
        op,
        hex_u64(ia_id),
        hex_u32(pool_id),
        handle,
        bundle_b64,
        hex_u64(nonce)
    );
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(base.as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice()) == signature
}

fn build_cap_resp_ok(secret: &[u8], nonce: u64, payload: &[u8]) -> String {
    let len = payload.len() as u32;
    let sig = sign_capture_response(secret, "ok", nonce, len, Some(payload), None);
    format!(
        "CAP_RESP;v=1;status=ok;nonce={};len={};sig={};payload={}",
        nonce,
        len,
        sig,
        hex_encode(payload)
    )
}

fn sign_capture_response(
    secret: &[u8],
    status: &str,
    nonce: u64,
    len: u32,
    payload: Option<&[u8]>,
    code: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(status.as_bytes());
    if status == "ok" {
        hasher.update(nonce.to_le_bytes());
        hasher.update(len.to_le_bytes());
        if let Some(payload) = payload {
            hasher.update(payload);
        }
    } else {
        hasher.update(nonce.to_le_bytes());
        if let Some(code) = code {
            hasher.update(code.as_bytes());
        }
    }
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn sign_cap_ok(resp_b64: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("CAP_OK;v=1;resp={}", resp_b64).as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn sign_cap_err(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("CAP_ERR;v=1;code={}", code).as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn verify_boot_request_sig(secret: &[u8], nonce_hex: &str, signature: &str) -> bool {
    let base = format!(
        "AI_BOOT_REQ;v=1;op=BOOT;mode=run;first_run=1;nonce={}",
        nonce_hex
    );
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(base.as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice()) == signature
}

fn sign_boot_ok(secret: &[u8], ia_id: u64, secret_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(format!("AI_BOOT_OK;v=1;ia_id={};secret={}", hex_u64(ia_id), secret_hex).as_bytes());
    let digest = hasher.finalize();
    hex_encode(digest.as_slice())
}

fn generate_capture_payload(op: &str, len: usize, nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let op_bytes = op.as_bytes();
    for i in 0..len {
        let ob = op_bytes.get(i % op_bytes.len().max(1)).copied().unwrap_or(0);
        let v = (ob as u64).wrapping_add(nonce).wrapping_add(i as u64);
        out.push((v & 0xff) as u8);
    }
    out
}

fn parse_hex_u64(input: &str) -> Option<u64> {
    u64::from_str_radix(input, 16).ok()
}

fn parse_hex_u32(input: &str) -> Option<u32> {
    u32::from_str_radix(input, 16).ok()
}

fn hex_u64_16(value: u64) -> String {
    format!("{:016x}", value)
}

fn hex_u64(value: u64) -> String {
    format!("{:032x}", value)
}

fn hex_u32(value: u32) -> String {
    format!("{:08x}", value)
}

fn secret_hex32(secret: &[u8]) -> String {
    let mut out = Vec::with_capacity(32);
    let mut count = 0;
    for &b in secret.iter() {
        if count >= 16 {
            break;
        }
        out.push(b"0123456789abcdef"[(b >> 4) as usize]);
        out.push(b"0123456789abcdef"[(b & 0x0f) as usize]);
        count += 1;
    }
    while count < 16 {
        out.push(b'0');
        out.push(b'0');
        count += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn base64_encode_no_pad(input: &[u8]) -> String {
    const LUT: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(((input.len() + 2) / 3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(LUT[(b0 >> 2) as usize]);
        out.push(LUT[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(LUT[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
        out.push(LUT[(b2 & 0x3f) as usize]);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out.push(LUT[(b0 >> 2) as usize]);
        out.push(LUT[((b0 & 0x03) << 4) as usize]);
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(LUT[(b0 >> 2) as usize]);
        out.push(LUT[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(LUT[((b1 & 0x0f) << 2) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn base64_decode_no_pad(input: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize]);
        out.push(LUT[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn noop_task(_context: &ExecutionContext) -> u32 {
    0
}

impl Default for TLSIntegrationManager {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_runtime::block_on;

    #[test]
    fn test_tls_authentication() {
        block_on(async {
        let manager = TLSIntegrationManager::new();
        assert!(!manager.is_authenticated());

        let token = "test_token_123456";
        let secret = "secret_key_123456";
        let _ = manager.authenticate(token.into(), secret, 42);
        assert!(manager.is_authenticated());

        let ctx = manager.get_context();
        assert_eq!(ctx.get_token().map(|s| s.as_str()), Some(token));
        assert!(ctx.verify_token(token, secret));
        });
    }

    #[test]
    fn test_tls_reset() {
        block_on(async {
        let manager = TLSIntegrationManager::new();
        let token = "token_1234567890";
        let secret = "secret_key_123456";
        let _ = manager.authenticate(token.into(), secret, 7);
        assert!(manager.is_authenticated());

        manager.reset();
        assert!(!manager.is_authenticated());
        });
    }
}
