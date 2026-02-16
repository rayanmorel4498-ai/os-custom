use crate::core::ai_core::AICore;
use crate::core::global_state::GlobalStateManager;
use crate::core::model_cache::ModelCache;
use crate::core::ai_watchdog::AIWatchdog;
use crate::core::local_profiler::LocalProfiler;
use crate::core::adaptive_scheduler::AdaptiveScheduler;
use crate::core::anomaly_detector::AnomalyDetector;
use crate::core::safe_ai::SafeAIMode;
use crate::core::auto_repair::AutoRepair;
use crate::core::sensor_manager::SensorManager;
use crate::core::app_prioritizer::AppPrioritizer;
use crate::core::perf_regression::PerfRegressionDetector;
use crate::core::privacy_mode::PrivacyMode;
use crate::core::predictive_cache::PredictiveCache;
use crate::core::energy_predictive::EnergyPredictiveModel;
use crate::core::local_alerts::LocalAlertSystem;
use crate::core::ai_zones::AIZoneIsolation;
use crate::core::semantic_cache::SemanticCache;
use crate::core::degraded_mode::DegradedMode;
use crate::core::adaptive_memory::AdaptiveMemoryOptimizer;
use crate::core::app_parasite::AppParasiteDetector;
use crate::core::network_scheduler::NetworkScheduler;
use crate::core::heat_forecast::HeatForecast;
use crate::core::sensor_calibration::SensorAutoCalibration;
use crate::core::storage_proactive::ProactiveStorageManager;
use crate::core::quiet_mode::QuietMode;
use crate::core::gpu_auto_profile::GpuAutoProfiler;
use crate::core::session_focus::SessionFocus;
use crate::core::preallocation::SmartPreallocator;
use crate::core::behavioral_malware::BehavioralMalwareDetector;
use crate::core::long_term_memory::LongTermMemory;
use crate::core::agenda_context::AgendaContext;
use crate::core::user_rules::UserRules;
use crate::core::personality::PersonalityProfile;
use crate::core::explainability::ExplainabilityStore;
use crate::core::silent_mode::SilentMode;
use crate::core::policy_engine::PolicyEngine;
use crate::core::multi_app_context::MultiAppContext;
use crate::core::low_power_mode::LowPowerAIMode;
use crate::core::score_calibration::ScoreCalibration;
use crate::modules::domain_rules;
use crate::modules::api::{SensorApi, AppPrioritizerApi, GpuProfilerApi, PolicyApi, QuotaApi, CacheApi};

use crate::core::timekeeper::Timekeeper;
use crate::core::resource_quota::ResourceQuotaManager;
use crate::core::sandbox_controller::{ActionType, ModuleCapabilities, SandboxController};
use crate::security::tls::bundle as tls_bundle;

#[cfg(feature = "offline_pretraining")]
use crate::core::offline_pretraining::run_offline_pretraining;
use crate::prelude::{String, format};
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};
use alloc::vec::Vec;

static MODEL_CACHE: Mutex<Option<ModelCache>> = Mutex::new(None);
static WATCHDOG: Mutex<Option<AIWatchdog>> = Mutex::new(None);
static LOCAL_PROFILER: Mutex<Option<LocalProfiler>> = Mutex::new(None);
static ADAPTIVE_SCHEDULER: Mutex<Option<AdaptiveScheduler>> = Mutex::new(None);
static ANOMALY_DETECTOR: Mutex<Option<AnomalyDetector>> = Mutex::new(None);
static SAFE_AI_MODE: Mutex<Option<SafeAIMode>> = Mutex::new(None);
static AUTO_REPAIR: Mutex<Option<AutoRepair>> = Mutex::new(None);
static SENSOR_MANAGER: Mutex<Option<SensorManager>> = Mutex::new(None);
static APP_PRIORITIZER: Mutex<Option<AppPrioritizer>> = Mutex::new(None);
static PERF_REGRESSION: Mutex<Option<PerfRegressionDetector>> = Mutex::new(None);
static PRIVACY_MODE: Mutex<Option<PrivacyMode>> = Mutex::new(None);
static PREDICTIVE_CACHE: Mutex<Option<PredictiveCache>> = Mutex::new(None);
static ENERGY_PREDICTIVE: Mutex<Option<EnergyPredictiveModel>> = Mutex::new(None);
static LOCAL_ALERTS: Mutex<Option<LocalAlertSystem>> = Mutex::new(None);
static AI_ZONES: Mutex<Option<AIZoneIsolation>> = Mutex::new(None);
static SEMANTIC_CACHE: Mutex<Option<SemanticCache>> = Mutex::new(None);
static DEGRADED_MODE: Mutex<Option<DegradedMode>> = Mutex::new(None);
static ADAPTIVE_MEMORY: Mutex<Option<AdaptiveMemoryOptimizer>> = Mutex::new(None);
static APP_PARASITE: Mutex<Option<AppParasiteDetector>> = Mutex::new(None);
static NETWORK_SCHEDULER: Mutex<Option<NetworkScheduler>> = Mutex::new(None);
static HEAT_FORECAST: Mutex<Option<HeatForecast>> = Mutex::new(None);
static SENSOR_CALIBRATION: Mutex<Option<SensorAutoCalibration>> = Mutex::new(None);
static STORAGE_PROACTIVE: Mutex<Option<ProactiveStorageManager>> = Mutex::new(None);
static QUIET_MODE: Mutex<Option<QuietMode>> = Mutex::new(None);
static GPU_AUTO_PROFILE: Mutex<Option<GpuAutoProfiler>> = Mutex::new(None);
static SESSION_FOCUS: Mutex<Option<SessionFocus>> = Mutex::new(None);
static PREALLOCATION: Mutex<Option<SmartPreallocator>> = Mutex::new(None);
static BEHAVIORAL_MALWARE: Mutex<Option<BehavioralMalwareDetector>> = Mutex::new(None);
static LONG_TERM_MEMORY: Mutex<Option<LongTermMemory>> = Mutex::new(None);
static AGENDA_CONTEXT: Mutex<Option<AgendaContext>> = Mutex::new(None);
static USER_RULES: Mutex<Option<UserRules>> = Mutex::new(None);
static PERSONALITY: Mutex<Option<PersonalityProfile>> = Mutex::new(None);
static EXPLAINABILITY: Mutex<Option<ExplainabilityStore>> = Mutex::new(None);
static SILENT_MODE: Mutex<Option<SilentMode>> = Mutex::new(None);
static POLICY_ENGINE: Mutex<Option<PolicyEngine>> = Mutex::new(None);
static MULTI_APP_CONTEXT: Mutex<Option<MultiAppContext>> = Mutex::new(None);
static LOW_POWER_AI: Mutex<Option<LowPowerAIMode>> = Mutex::new(None);
static SCORE_CALIBRATION: Mutex<Option<ScoreCalibration>> = Mutex::new(None);
static TIMEKEEPER: Mutex<Option<Timekeeper>> = Mutex::new(None);
static RESOURCE_QUOTA: Mutex<Option<ResourceQuotaManager>> = Mutex::new(None);
static SANDBOX: Mutex<Option<Arc<SandboxController>>> = Mutex::new(None);
static IA_LOCKED: AtomicBool = AtomicBool::new(true);
static INIT_STATE: Once<()> = Once::new();
static INIT_RESULT: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static INIT_REPORT: Mutex<InitReport> = Mutex::new(InitReport::new());

const IA_BUNDLE_TTL_SECS: u64 = 10;
const KERNEL_BUNDLE_TTL_SECS: u64 = 60;
const HARDWARE_BUNDLE_TTL_SECS: u64 = 30;

#[derive(Clone, Debug, Default)]
pub struct InitReport {
	pub completed: bool,
	pub warnings: Vec<String>,
	pub failures: Vec<String>,
}

impl InitReport {
	const fn new() -> Self {
		InitReport {
			completed: false,
			warnings: Vec::new(),
			failures: Vec::new(),
		}
	}
}

pub fn init() -> Result<(), String> {
	init_ia().map(|_| ())
}

pub fn init_ia() -> Result<AICore, String> {
	let core = AICore::new();
	set_locked(true);
	let now_ms = crate::time::now_ms();
	tls_bundle::set_client(core.tls_client().clone());
	if tls_bundle::handshake_and_store_for_with_ttl(
		"ia",
		now_ms,
		Some(IA_BUNDLE_TTL_SECS),
	)
	.is_err()
	{
		return Err("init: tls bundle invalid".to_string());
	}
	set_locked(false);
	let _ = tls_bundle::handshake_and_store_for_with_ttl(
		"kernel",
		now_ms,
		Some(KERNEL_BUNDLE_TTL_SECS),
	);
	let _ = tls_bundle::handshake_and_store_for_with_ttl(
		"hardware",
		now_ms,
		Some(HARDWARE_BUNDLE_TTL_SECS),
	);

	INIT_STATE.call_once(|| {
		let result = (|| {
			let mut report = InitReport::default();

			if SANDBOX.lock().is_none() {
				let sandbox = init_sandbox_defaults();
				*SANDBOX.lock() = Some(sandbox);
			}

			if MODEL_CACHE.lock().is_none() {
				let cache = init_model_cache(2048);
				let loaded = cache.preload_defaults();
				if loaded == 0 {
					report.warnings.push("init: model cache preload failed".to_string());
				}
				#[cfg(feature = "offline_pretraining")]
				let _metrics = run_offline_pretraining(&cache);
				*MODEL_CACHE.lock() = Some(cache);
			}

			if let Err(err) = domain_rules::validate_no_cycles() {
				report.warnings.push(format!("init: module deps {}", err));
			}

			if WATCHDOG.lock().is_none() {
				*WATCHDOG.lock() = Some(AIWatchdog::new());
			}
			if LOCAL_PROFILER.lock().is_none() {
				*LOCAL_PROFILER.lock() = Some(LocalProfiler::new());
			}
			if ADAPTIVE_SCHEDULER.lock().is_none() {
				let mut sched = AdaptiveScheduler::new();
				sched.set_hard_budget(16.0, 8.0, 12.0);
				*ADAPTIVE_SCHEDULER.lock() = Some(sched);
			}
			if ANOMALY_DETECTOR.lock().is_none() {
				*ANOMALY_DETECTOR.lock() = Some(AnomalyDetector::new());
			}
			if SAFE_AI_MODE.lock().is_none() {
				*SAFE_AI_MODE.lock() = Some(SafeAIMode::new());
			}
			if AUTO_REPAIR.lock().is_none() {
				*AUTO_REPAIR.lock() = Some(AutoRepair::new());
				let _ = with_auto_repair_mut(|repair| {
					repair.register_module_restart("ai_core", restart_ai_core_hook);
					repair.register_module_restart("sensors", restart_sensors_hook);
					repair.register_module_restart("apps", restart_apps_hook);
					repair.register_module_restart("gpu", restart_gpu_hook);
					repair.register_module_rollback("sensors", restart_sensors_hook);
					repair.register_module_rollback("apps", restart_apps_hook);
					repair.register_module_rollback("gpu", restart_gpu_hook);
				});
			}
			if SENSOR_MANAGER.lock().is_none() {
				*SENSOR_MANAGER.lock() = Some(SensorManager::new());
			}
			if APP_PRIORITIZER.lock().is_none() {
				*APP_PRIORITIZER.lock() = Some(AppPrioritizer::new());
			}
			if PERF_REGRESSION.lock().is_none() {
				*PERF_REGRESSION.lock() = Some(PerfRegressionDetector::new());
			}
			if PRIVACY_MODE.lock().is_none() {
				*PRIVACY_MODE.lock() = Some(PrivacyMode::new());
			}
			if PREDICTIVE_CACHE.lock().is_none() {
				*PREDICTIVE_CACHE.lock() = Some(PredictiveCache::new());
			}
			if ENERGY_PREDICTIVE.lock().is_none() {
				*ENERGY_PREDICTIVE.lock() = Some(EnergyPredictiveModel::new());
			}
			if LOCAL_ALERTS.lock().is_none() {
				*LOCAL_ALERTS.lock() = Some(LocalAlertSystem::new());
			}
			if AI_ZONES.lock().is_none() {
				*AI_ZONES.lock() = Some(AIZoneIsolation::new());
			}
			if SEMANTIC_CACHE.lock().is_none() {
				*SEMANTIC_CACHE.lock() = Some(SemanticCache::new(1024));
			}
			if DEGRADED_MODE.lock().is_none() {
				*DEGRADED_MODE.lock() = Some(DegradedMode::new());
			}
			if ADAPTIVE_MEMORY.lock().is_none() {
				*ADAPTIVE_MEMORY.lock() = Some(AdaptiveMemoryOptimizer::new());
			}
			if APP_PARASITE.lock().is_none() {
				*APP_PARASITE.lock() = Some(AppParasiteDetector::new());
			}
			if NETWORK_SCHEDULER.lock().is_none() {
				*NETWORK_SCHEDULER.lock() = Some(NetworkScheduler::new());
			}
			if HEAT_FORECAST.lock().is_none() {
				*HEAT_FORECAST.lock() = Some(HeatForecast::new());
			}
			if SENSOR_CALIBRATION.lock().is_none() {
				*SENSOR_CALIBRATION.lock() = Some(SensorAutoCalibration::new());
			}
			if STORAGE_PROACTIVE.lock().is_none() {
				*STORAGE_PROACTIVE.lock() = Some(ProactiveStorageManager::new());
			}
			if QUIET_MODE.lock().is_none() {
				*QUIET_MODE.lock() = Some(QuietMode::new());
			}
			if GPU_AUTO_PROFILE.lock().is_none() {
				*GPU_AUTO_PROFILE.lock() = Some(GpuAutoProfiler::new());
			}
			if SESSION_FOCUS.lock().is_none() {
				*SESSION_FOCUS.lock() = Some(SessionFocus::new());
			}
			if PREALLOCATION.lock().is_none() {
				*PREALLOCATION.lock() = Some(SmartPreallocator::new());
			}
			if BEHAVIORAL_MALWARE.lock().is_none() {
				*BEHAVIORAL_MALWARE.lock() = Some(BehavioralMalwareDetector::new());
			}
			if LONG_TERM_MEMORY.lock().is_none() {
				*LONG_TERM_MEMORY.lock() = Some(LongTermMemory::new());
			}
			if AGENDA_CONTEXT.lock().is_none() {
				*AGENDA_CONTEXT.lock() = Some(AgendaContext::new());
			}
			if USER_RULES.lock().is_none() {
				*USER_RULES.lock() = Some(UserRules::new());
			}
			if PERSONALITY.lock().is_none() {
				*PERSONALITY.lock() = Some(PersonalityProfile::new());
			}
			if EXPLAINABILITY.lock().is_none() {
				*EXPLAINABILITY.lock() = Some(ExplainabilityStore::new(256));
			}
			if SILENT_MODE.lock().is_none() {
				*SILENT_MODE.lock() = Some(SilentMode::new());
			}
			if POLICY_ENGINE.lock().is_none() {
				*POLICY_ENGINE.lock() = Some(PolicyEngine::new());
			}
			if MULTI_APP_CONTEXT.lock().is_none() {
				*MULTI_APP_CONTEXT.lock() = Some(MultiAppContext::new());
			}
			if LOW_POWER_AI.lock().is_none() {
				*LOW_POWER_AI.lock() = Some(LowPowerAIMode::new());
			}
			if SCORE_CALIBRATION.lock().is_none() {
				*SCORE_CALIBRATION.lock() = Some(ScoreCalibration::new());
			}
			if TIMEKEEPER.lock().is_none() {
				*TIMEKEEPER.lock() = Some(Timekeeper::new());
			}
			if RESOURCE_QUOTA.lock().is_none() {
				*RESOURCE_QUOTA.lock() = Some(ResourceQuotaManager::new());
				let _ = with_resource_quota_mut(|quota| {
					quota.set_budget("sensors", 8, 0, 32, 10);
					quota.set_budget("apps", 6, 0, 64, 12);
					quota.set_budget("ui", 4, 1, 32, 16);
					quota.set_budget("gpu", 2, 8, 128, 20);
				});
			}

			let global_state = GlobalStateManager::new();
			global_state.set_module_status(0, true);
			global_state.set_module_status(1, true);
			global_state.set_module_status(2, true);
			global_state.set_module_status(3, true);
			global_state.snapshot();

			report.completed = true;
			*INIT_REPORT.lock() = report.clone();
			Ok(())
		})();
		*INIT_RESULT.lock() = Some(result);
	});

	match INIT_RESULT.lock().as_ref() {
		Some(Ok(())) => Ok(core),
		Some(Err(err)) => Err(err.clone()),
		None => Err("init: unknown state".to_string()),
	}
}

pub fn init_report() -> InitReport {
	INIT_REPORT.lock().clone()
}

pub fn is_locked() -> bool {
	IA_LOCKED.load(Ordering::Relaxed)
}

pub fn set_locked(locked: bool) {
	IA_LOCKED.store(locked, Ordering::Relaxed);
}

pub fn init_model_cache(capacity_mb: u32) -> ModelCache {
	let cache = ModelCache::new(capacity_mb);
	cache
}

fn restart_ai_core_hook() -> bool {
	let _ = with_safe_ai_mut(|safe| safe.reset());
	let _ = with_timekeeper_mut(|tk| tk.reset());
	let _ = with_resource_quota_mut(|quota| quota.reset_window());
	let _ = with_local_profiler_mut(|prof| prof.reset());
	true
}

fn restart_sensors_hook() -> bool {
	with_sensor_manager_mut(|mgr| {
		*mgr = SensorManager::new();
	}).is_some()
}

fn restart_apps_hook() -> bool {
	with_app_prioritizer_mut(|apps| {
		*apps = AppPrioritizer::new();
	}).is_some()
}

fn restart_gpu_hook() -> bool {
	with_gpu_auto_profile_mut(|gpu| {
		*gpu = GpuAutoProfiler::new();
	}).is_some()
}

pub fn with_sandbox<R>(f: impl FnOnce(&Arc<SandboxController>) -> R) -> Option<R> {
	SANDBOX.lock().as_ref().map(f)
}

pub fn sandbox_validate_action(
	module: &str,
	action: ActionType,
	cpu_ms: u64,
	ram_mb: u64,
	io_ops: u64,
) -> bool {
	with_sandbox(|sandbox| {
		let mut params: BTreeMap<String, String> = BTreeMap::new();
		params.insert("module".into(), module.into());
		params.insert("cpu_ms".into(), cpu_ms.to_string());
		params.insert("ram_mb".into(), ram_mb.to_string());
		params.insert("io_ops".into(), io_ops.to_string());
		params.insert("context".into(), "runtime".into());
		block_on(async { sandbox.validate_action(action, params).await }).is_ok()
	})
	.unwrap_or(false)
}

fn init_sandbox_defaults() -> Arc<SandboxController> {
	let sandbox = Arc::new(SandboxController::new());
	let caps_kernel = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: false,
		gpu: false,
		kernel: true,
		device: false,
		storage: false,
		system: true,
		memory: true,
		power: true,
	};
	let caps_storage = ModuleCapabilities {
		fs: true,
		network: false,
		ipc: false,
		gpu: false,
		kernel: false,
		device: false,
		storage: true,
		system: false,
		memory: false,
		power: false,
	};
	let caps_ipc = ModuleCapabilities {
		fs: false,
		network: true,
		ipc: true,
		gpu: false,
		kernel: false,
		device: false,
		storage: false,
		system: false,
		memory: false,
		power: false,
	};
	let caps_device = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: false,
		gpu: false,
		kernel: false,
		device: true,
		storage: false,
		system: false,
		memory: false,
		power: false,
	};
	let caps_gpu = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: false,
		gpu: true,
		kernel: false,
		device: true,
		storage: false,
		system: false,
		memory: false,
		power: false,
	};
	let caps_system = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: false,
		gpu: false,
		kernel: false,
		device: false,
		storage: false,
		system: true,
		memory: false,
		power: false,
	};
	let caps_sensors = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: false,
		gpu: false,
		kernel: false,
		device: true,
		storage: false,
		system: false,
		memory: false,
		power: false,
	};
	let caps_apps = ModuleCapabilities {
		fs: false,
		network: false,
		ipc: true,
		gpu: false,
		kernel: false,
		device: false,
		storage: false,
		system: true,
		memory: false,
		power: false,
	};
	let caps_ui = ModuleCapabilities {
		fs: false,
		network: true,
		ipc: true,
		gpu: false,
		kernel: false,
		device: false,
		storage: false,
		system: false,
		memory: false,
		power: false,
	};

	block_on(async {
		sandbox.allowlist_action(ActionType::KernelMemory, true).await;
		sandbox.set_module_capabilities("kernel", caps_kernel).await;
		sandbox.set_module_capabilities("storage", caps_storage).await;
		sandbox.set_module_capabilities("ipc", caps_ipc).await;
		sandbox.set_module_capabilities("device", caps_device).await;
		sandbox.set_module_capabilities("gpu", caps_gpu).await;
		sandbox.set_module_capabilities("system", caps_system).await;
		sandbox.set_module_capabilities("sensors", caps_sensors).await;
		sandbox.set_module_capabilities("apps", caps_apps).await;
		sandbox.set_module_capabilities("ui", caps_ui).await;

		sandbox
			.set_module_limits_full("kernel", 10, 256, 64, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("storage", 10, 1024, 256, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("ipc", 5, 64, 512, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("device", 5, 64, 128, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("gpu", 8, 256, 128, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("system", 5, 64, 64, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("sensors", 5, 64, 64, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("apps", 5, 64, 64, 1_000, 5, 5_000)
			.await;
		sandbox
			.set_module_limits_full("ui", 5, 64, 64, 1_000, 5, 5_000)
			.await;
	});

	sandbox
}

fn block_on<F: Future>(future: F) -> F::Output {
	fn no_op(_: *const ()) {}
	fn clone(_: *const ()) -> RawWaker {
		RawWaker::new(core::ptr::null(), &VTABLE)
	}
	static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
	let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
	let mut context = Context::from_waker(&waker);
	let mut future = Box::pin(future);
	let mut spins: u32 = 0;
	const SPIN_YIELD_INTERVAL: u32 = 1024;
	const MAX_SPINS: u32 = 5_000_000;
	loop {
		match Pin::new(&mut future).poll(&mut context) {
			Poll::Ready(output) => return output,
			Poll::Pending => {
				spins = spins.saturating_add(1);
				if spins % SPIN_YIELD_INTERVAL == 0 {
					core::hint::spin_loop();
				}
				if spins >= MAX_SPINS {
					panic!("block_on timeout (future never became ready)");
				}
				core::hint::spin_loop();
			}
		}
	}
}

pub fn with_model_cache<R>(f: impl FnOnce(&ModelCache) -> R) -> Option<R> {
	MODEL_CACHE.lock().as_ref().map(f)
}

pub fn with_cache_api<R>(f: impl FnOnce(&dyn CacheApi) -> R) -> Option<R> {
	MODEL_CACHE
		.lock()
		.as_ref()
		.map(|cache| f(cache as &dyn CacheApi))
}

pub fn with_watchdog<R>(f: impl FnOnce(&AIWatchdog) -> R) -> Option<R> {
	WATCHDOG.lock().as_ref().map(f)
}

pub fn with_watchdog_mut<R>(f: impl FnOnce(&mut AIWatchdog) -> R) -> Option<R> {
	WATCHDOG.lock().as_mut().map(f)
}

pub fn with_local_profiler<R>(f: impl FnOnce(&LocalProfiler) -> R) -> Option<R> {
	LOCAL_PROFILER.lock().as_ref().map(f)
}

pub fn with_local_profiler_mut<R>(f: impl FnOnce(&mut LocalProfiler) -> R) -> Option<R> {
	LOCAL_PROFILER.lock().as_mut().map(f)
}

pub fn with_adaptive_scheduler<R>(f: impl FnOnce(&AdaptiveScheduler) -> R) -> Option<R> {
	ADAPTIVE_SCHEDULER.lock().as_ref().map(f)
}

pub fn with_adaptive_scheduler_mut<R>(f: impl FnOnce(&mut AdaptiveScheduler) -> R) -> Option<R> {
	ADAPTIVE_SCHEDULER.lock().as_mut().map(f)
}

pub fn with_anomaly_detector<R>(f: impl FnOnce(&AnomalyDetector) -> R) -> Option<R> {
	ANOMALY_DETECTOR.lock().as_ref().map(f)
}

pub fn with_anomaly_detector_mut<R>(f: impl FnOnce(&mut AnomalyDetector) -> R) -> Option<R> {
	ANOMALY_DETECTOR.lock().as_mut().map(f)
}

pub fn with_safe_ai<R>(f: impl FnOnce(&SafeAIMode) -> R) -> Option<R> {
	SAFE_AI_MODE.lock().as_ref().map(f)
}

pub fn with_safe_ai_mut<R>(f: impl FnOnce(&mut SafeAIMode) -> R) -> Option<R> {
	SAFE_AI_MODE.lock().as_mut().map(f)
}

pub fn with_auto_repair<R>(f: impl FnOnce(&AutoRepair) -> R) -> Option<R> {
	AUTO_REPAIR.lock().as_ref().map(f)
}

pub fn with_auto_repair_mut<R>(f: impl FnOnce(&mut AutoRepair) -> R) -> Option<R> {
	AUTO_REPAIR.lock().as_mut().map(f)
}

pub fn with_sensor_manager<R>(f: impl FnOnce(&SensorManager) -> R) -> Option<R> {
	SENSOR_MANAGER.lock().as_ref().map(f)
}

pub fn with_sensor_manager_mut<R>(f: impl FnOnce(&mut SensorManager) -> R) -> Option<R> {
	SENSOR_MANAGER.lock().as_mut().map(f)
}

pub fn with_sensor_api_mut<R>(f: impl FnOnce(&mut dyn SensorApi) -> R) -> Option<R> {
	SENSOR_MANAGER
		.lock()
		.as_mut()
		.map(|mgr| f(mgr as &mut dyn SensorApi))
}

pub fn with_app_prioritizer<R>(f: impl FnOnce(&AppPrioritizer) -> R) -> Option<R> {
	APP_PRIORITIZER.lock().as_ref().map(f)
}

pub fn with_app_prioritizer_mut<R>(f: impl FnOnce(&mut AppPrioritizer) -> R) -> Option<R> {
	APP_PRIORITIZER.lock().as_mut().map(f)
}

pub fn with_app_prioritizer_api_mut<R>(f: impl FnOnce(&mut dyn AppPrioritizerApi) -> R) -> Option<R> {
	APP_PRIORITIZER
		.lock()
		.as_mut()
		.map(|apps| f(apps as &mut dyn AppPrioritizerApi))
}

pub fn with_perf_regression<R>(f: impl FnOnce(&PerfRegressionDetector) -> R) -> Option<R> {
	PERF_REGRESSION.lock().as_ref().map(f)
}

pub fn with_perf_regression_mut<R>(f: impl FnOnce(&mut PerfRegressionDetector) -> R) -> Option<R> {
	PERF_REGRESSION.lock().as_mut().map(f)
}

pub fn with_privacy_mode<R>(f: impl FnOnce(&PrivacyMode) -> R) -> Option<R> {
	PRIVACY_MODE.lock().as_ref().map(f)
}

pub fn with_privacy_mode_mut<R>(f: impl FnOnce(&mut PrivacyMode) -> R) -> Option<R> {
	PRIVACY_MODE.lock().as_mut().map(f)
}

pub fn with_predictive_cache<R>(f: impl FnOnce(&PredictiveCache) -> R) -> Option<R> {
	PREDICTIVE_CACHE.lock().as_ref().map(f)
}

pub fn with_predictive_cache_mut<R>(f: impl FnOnce(&mut PredictiveCache) -> R) -> Option<R> {
	PREDICTIVE_CACHE.lock().as_mut().map(f)
}

pub fn with_energy_predictive<R>(f: impl FnOnce(&EnergyPredictiveModel) -> R) -> Option<R> {
	ENERGY_PREDICTIVE.lock().as_ref().map(f)
}

pub fn with_energy_predictive_mut<R>(f: impl FnOnce(&mut EnergyPredictiveModel) -> R) -> Option<R> {
	ENERGY_PREDICTIVE.lock().as_mut().map(f)
}

pub fn with_local_alerts<R>(f: impl FnOnce(&LocalAlertSystem) -> R) -> Option<R> {
	LOCAL_ALERTS.lock().as_ref().map(f)
}

pub fn with_local_alerts_mut<R>(f: impl FnOnce(&mut LocalAlertSystem) -> R) -> Option<R> {
	LOCAL_ALERTS.lock().as_mut().map(f)
}

pub fn with_ai_zones<R>(f: impl FnOnce(&AIZoneIsolation) -> R) -> Option<R> {
	AI_ZONES.lock().as_ref().map(f)
}

pub fn with_ai_zones_mut<R>(f: impl FnOnce(&mut AIZoneIsolation) -> R) -> Option<R> {
	AI_ZONES.lock().as_mut().map(f)
}

pub fn with_semantic_cache<R>(f: impl FnOnce(&SemanticCache) -> R) -> Option<R> {
	SEMANTIC_CACHE.lock().as_ref().map(f)
}

pub fn with_semantic_cache_mut<R>(f: impl FnOnce(&mut SemanticCache) -> R) -> Option<R> {
	SEMANTIC_CACHE.lock().as_mut().map(f)
}

pub fn with_degraded_mode<R>(f: impl FnOnce(&DegradedMode) -> R) -> Option<R> {
	DEGRADED_MODE.lock().as_ref().map(f)
}

pub fn with_degraded_mode_mut<R>(f: impl FnOnce(&mut DegradedMode) -> R) -> Option<R> {
	DEGRADED_MODE.lock().as_mut().map(f)
}

pub fn with_adaptive_memory<R>(f: impl FnOnce(&AdaptiveMemoryOptimizer) -> R) -> Option<R> {
	ADAPTIVE_MEMORY.lock().as_ref().map(f)
}

pub fn with_adaptive_memory_mut<R>(f: impl FnOnce(&mut AdaptiveMemoryOptimizer) -> R) -> Option<R> {
	ADAPTIVE_MEMORY.lock().as_mut().map(f)
}

pub fn with_app_parasite<R>(f: impl FnOnce(&AppParasiteDetector) -> R) -> Option<R> {
	APP_PARASITE.lock().as_ref().map(f)
}

pub fn with_app_parasite_mut<R>(f: impl FnOnce(&mut AppParasiteDetector) -> R) -> Option<R> {
	APP_PARASITE.lock().as_mut().map(f)
}

pub fn with_network_scheduler<R>(f: impl FnOnce(&NetworkScheduler) -> R) -> Option<R> {
	NETWORK_SCHEDULER.lock().as_ref().map(f)
}

pub fn with_network_scheduler_mut<R>(f: impl FnOnce(&mut NetworkScheduler) -> R) -> Option<R> {
	NETWORK_SCHEDULER.lock().as_mut().map(f)
}

pub fn with_heat_forecast<R>(f: impl FnOnce(&HeatForecast) -> R) -> Option<R> {
	HEAT_FORECAST.lock().as_ref().map(f)
}

pub fn with_heat_forecast_mut<R>(f: impl FnOnce(&mut HeatForecast) -> R) -> Option<R> {
	HEAT_FORECAST.lock().as_mut().map(f)
}

pub fn with_sensor_calibration<R>(f: impl FnOnce(&SensorAutoCalibration) -> R) -> Option<R> {
	SENSOR_CALIBRATION.lock().as_ref().map(f)
}

pub fn with_sensor_calibration_mut<R>(f: impl FnOnce(&mut SensorAutoCalibration) -> R) -> Option<R> {
	SENSOR_CALIBRATION.lock().as_mut().map(f)
}

pub fn with_storage_proactive<R>(f: impl FnOnce(&ProactiveStorageManager) -> R) -> Option<R> {
	STORAGE_PROACTIVE.lock().as_ref().map(f)
}

pub fn with_storage_proactive_mut<R>(f: impl FnOnce(&mut ProactiveStorageManager) -> R) -> Option<R> {
	STORAGE_PROACTIVE.lock().as_mut().map(f)
}

pub fn with_quiet_mode<R>(f: impl FnOnce(&QuietMode) -> R) -> Option<R> {
	QUIET_MODE.lock().as_ref().map(f)
}

pub fn with_quiet_mode_mut<R>(f: impl FnOnce(&mut QuietMode) -> R) -> Option<R> {
	QUIET_MODE.lock().as_mut().map(f)
}

pub fn with_gpu_auto_profile<R>(f: impl FnOnce(&GpuAutoProfiler) -> R) -> Option<R> {
	GPU_AUTO_PROFILE.lock().as_ref().map(f)
}

pub fn with_gpu_auto_profile_mut<R>(f: impl FnOnce(&mut GpuAutoProfiler) -> R) -> Option<R> {
	GPU_AUTO_PROFILE.lock().as_mut().map(f)
}

pub fn with_gpu_profiler_api_mut<R>(f: impl FnOnce(&mut dyn GpuProfilerApi) -> R) -> Option<R> {
	GPU_AUTO_PROFILE
		.lock()
		.as_mut()
		.map(|gpu| f(gpu as &mut dyn GpuProfilerApi))
}

pub fn with_session_focus<R>(f: impl FnOnce(&SessionFocus) -> R) -> Option<R> {
	SESSION_FOCUS.lock().as_ref().map(f)
}

pub fn with_session_focus_mut<R>(f: impl FnOnce(&mut SessionFocus) -> R) -> Option<R> {
	SESSION_FOCUS.lock().as_mut().map(f)
}

pub fn with_preallocation<R>(f: impl FnOnce(&SmartPreallocator) -> R) -> Option<R> {
	PREALLOCATION.lock().as_ref().map(f)
}

pub fn with_preallocation_mut<R>(f: impl FnOnce(&mut SmartPreallocator) -> R) -> Option<R> {
	PREALLOCATION.lock().as_mut().map(f)
}

pub fn with_behavioral_malware<R>(f: impl FnOnce(&BehavioralMalwareDetector) -> R) -> Option<R> {
	BEHAVIORAL_MALWARE.lock().as_ref().map(f)
}

pub fn with_behavioral_malware_mut<R>(f: impl FnOnce(&mut BehavioralMalwareDetector) -> R) -> Option<R> {
	BEHAVIORAL_MALWARE.lock().as_mut().map(f)
}

pub fn with_long_term_memory<R>(f: impl FnOnce(&LongTermMemory) -> R) -> Option<R> {
	LONG_TERM_MEMORY.lock().as_ref().map(f)
}

pub fn with_long_term_memory_mut<R>(f: impl FnOnce(&mut LongTermMemory) -> R) -> Option<R> {
	LONG_TERM_MEMORY.lock().as_mut().map(f)
}

pub fn with_agenda_context<R>(f: impl FnOnce(&AgendaContext) -> R) -> Option<R> {
	AGENDA_CONTEXT.lock().as_ref().map(f)
}

pub fn with_agenda_context_mut<R>(f: impl FnOnce(&mut AgendaContext) -> R) -> Option<R> {
	AGENDA_CONTEXT.lock().as_mut().map(f)
}

pub fn with_user_rules<R>(f: impl FnOnce(&UserRules) -> R) -> Option<R> {
	USER_RULES.lock().as_ref().map(f)
}

pub fn with_user_rules_mut<R>(f: impl FnOnce(&mut UserRules) -> R) -> Option<R> {
	USER_RULES.lock().as_mut().map(f)
}

pub fn with_personality<R>(f: impl FnOnce(&PersonalityProfile) -> R) -> Option<R> {
	PERSONALITY.lock().as_ref().map(f)
}

pub fn with_personality_mut<R>(f: impl FnOnce(&mut PersonalityProfile) -> R) -> Option<R> {
	PERSONALITY.lock().as_mut().map(f)
}

pub fn with_explainability<R>(f: impl FnOnce(&ExplainabilityStore) -> R) -> Option<R> {
	EXPLAINABILITY.lock().as_ref().map(f)
}

pub fn with_explainability_mut<R>(f: impl FnOnce(&mut ExplainabilityStore) -> R) -> Option<R> {
	EXPLAINABILITY.lock().as_mut().map(f)
}

pub fn with_silent_mode<R>(f: impl FnOnce(&SilentMode) -> R) -> Option<R> {
	SILENT_MODE.lock().as_ref().map(f)
}

pub fn with_silent_mode_mut<R>(f: impl FnOnce(&mut SilentMode) -> R) -> Option<R> {
	SILENT_MODE.lock().as_mut().map(f)
}

pub fn with_policy_engine<R>(f: impl FnOnce(&PolicyEngine) -> R) -> Option<R> {
	POLICY_ENGINE.lock().as_ref().map(f)
}

pub fn with_policy_api<R>(f: impl FnOnce(&dyn PolicyApi) -> R) -> Option<R> {
	POLICY_ENGINE
		.lock()
		.as_ref()
		.map(|engine| f(engine as &dyn PolicyApi))
}

pub fn with_policy_engine_mut<R>(f: impl FnOnce(&mut PolicyEngine) -> R) -> Option<R> {
	POLICY_ENGINE.lock().as_mut().map(f)
}

pub fn with_multi_app_context<R>(f: impl FnOnce(&MultiAppContext) -> R) -> Option<R> {
	MULTI_APP_CONTEXT.lock().as_ref().map(f)
}

pub fn with_multi_app_context_mut<R>(f: impl FnOnce(&mut MultiAppContext) -> R) -> Option<R> {
	MULTI_APP_CONTEXT.lock().as_mut().map(f)
}

pub fn with_low_power_ai<R>(f: impl FnOnce(&LowPowerAIMode) -> R) -> Option<R> {
	LOW_POWER_AI.lock().as_ref().map(f)
}

pub fn with_low_power_ai_mut<R>(f: impl FnOnce(&mut LowPowerAIMode) -> R) -> Option<R> {
	LOW_POWER_AI.lock().as_mut().map(f)
}

pub fn with_score_calibration<R>(f: impl FnOnce(&ScoreCalibration) -> R) -> Option<R> {
	SCORE_CALIBRATION.lock().as_ref().map(f)
}

pub fn with_score_calibration_mut<R>(f: impl FnOnce(&mut ScoreCalibration) -> R) -> Option<R> {
	SCORE_CALIBRATION.lock().as_mut().map(f)
}

pub fn with_timekeeper<R>(f: impl FnOnce(&Timekeeper) -> R) -> Option<R> {
	TIMEKEEPER.lock().as_ref().map(f)
}

pub fn with_timekeeper_mut<R>(f: impl FnOnce(&mut Timekeeper) -> R) -> Option<R> {
	TIMEKEEPER.lock().as_mut().map(f)
}

pub fn with_resource_quota<R>(f: impl FnOnce(&ResourceQuotaManager) -> R) -> Option<R> {
	RESOURCE_QUOTA.lock().as_ref().map(f)
}

pub fn with_quota_api<R>(f: impl FnOnce(&dyn QuotaApi) -> R) -> Option<R> {
	RESOURCE_QUOTA
		.lock()
		.as_ref()
		.map(|quota| f(quota as &dyn QuotaApi))
}

pub fn with_resource_quota_mut<R>(f: impl FnOnce(&mut ResourceQuotaManager) -> R) -> Option<R> {
	RESOURCE_QUOTA.lock().as_mut().map(f)
}

pub fn purge_model_cache(current_tick: u64, interval_ticks: u64, max_models: usize) -> Option<u32> {
	MODEL_CACHE
		.lock()
		.as_ref()
		.map(|cache| cache.purge_periodic(current_tick, interval_ticks, max_models))
}

