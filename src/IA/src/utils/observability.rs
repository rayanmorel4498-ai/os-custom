use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use spin::{Mutex, Once};

#[derive(Clone, Copy, Default)]
struct TimerStats {
	sum_ms: u64,
	count: u64,
}

pub struct MetricsRegistry {
	counters: BTreeMap<String, u64>,
	gauges: BTreeMap<String, i64>,
	timers: BTreeMap<String, TimerStats>,
}

impl MetricsRegistry {
	pub fn new() -> Self {
		MetricsRegistry {
			counters: BTreeMap::new(),
			gauges: BTreeMap::new(),
			timers: BTreeMap::new(),
		}
	}

	pub fn inc_counter(&mut self, key: &str, delta: u64) {
		let entry = self.counters.entry(key.to_string()).or_insert(0);
		*entry = entry.saturating_add(delta);
	}

	pub fn set_gauge(&mut self, key: &str, value: i64) {
		self.gauges.insert(key.to_string(), value);
	}

	pub fn record_timer(&mut self, key: &str, duration_ms: u64) {
		let entry = self.timers.entry(key.to_string()).or_insert(TimerStats::default());
		entry.sum_ms = entry.sum_ms.saturating_add(duration_ms);
		entry.count = entry.count.saturating_add(1);
	}

	pub fn export_metrics(&self) -> String {
		let mut out = String::new();
		let ticks = self.counters.get("ticks").cloned().unwrap_or(0);
		let errors = self.counters.get("errors_total").cloned().unwrap_or(0);
		let safe_ai = self.counters.get("safe_ai_actions").cloned().unwrap_or(0);
		let ipc_drops = self.counters.get("ipc_drops").cloned().unwrap_or(0);
		let quota_throttles = self.counters.get("quota_throttles").cloned().unwrap_or(0);
		let latency_avg = self.avg_timer_ms("latence_moy_ms");
		let loop_latency = self.gauges.get("latence_boucle_ms").cloned().unwrap_or(0);
		let loop_latency_p95 = self.gauges.get("latence_boucle_p95_ms").cloned().unwrap_or(0);
		let loop_latency_p99 = self.gauges.get("latence_boucle_p99_ms").cloned().unwrap_or(0);
		let loop_jitter = self.gauges.get("latence_boucle_jitter_ms").cloned().unwrap_or(0);
		out.push_str(&alloc::format!(
			"ticks={},latence_moy_ms={:.2},latence_boucle_ms={},latence_boucle_p95_ms={},latence_boucle_p99_ms={},latence_boucle_jitter_ms={},errors_total={},safe_ai_actions={},ipc_drops={},quota_throttles={}",
			ticks,
			latency_avg,
			loop_latency,
			loop_latency_p95,
			loop_latency_p99,
			loop_jitter,
			errors,
			safe_ai,
			ipc_drops,
			quota_throttles
		));
		if !self.gauges.is_empty() {
			out.push_str(",gauges=");
			let mut first = true;
			for (key, value) in self.gauges.iter() {
				if !first {
					out.push(';');
				}
				first = false;
				out.push_str(key);
				out.push('=');
				out.push_str(&value.to_string());
			}
		}
		out
	}

	pub fn export_health(&self) -> String {
		let errors = self.counters.get("errors_total").cloned().unwrap_or(0);
		let status = if errors > 0 { "degraded" } else { "ok" };
		alloc::format!("status={},errors_total={}", status, errors)
	}

	fn avg_timer_ms(&self, key: &str) -> f32 {
		self.timers
			.get(key)
			.and_then(|t| {
				if t.count == 0 {
					None
				} else {
					Some((t.sum_ms as f32) / (t.count as f32))
				}
			})
			.unwrap_or(0.0)
	}
}

static METRICS: Once<Mutex<MetricsRegistry>> = Once::new();

fn registry() -> &'static Mutex<MetricsRegistry> {
	METRICS.call_once(|| Mutex::new(MetricsRegistry::new()))
}

pub fn inc_counter(key: &str, delta: u64) {
	registry().lock().inc_counter(key, delta);
}

pub fn set_gauge(key: &str, value: i64) {
	registry().lock().set_gauge(key, value);
}

pub fn record_timer(key: &str, duration_ms: u64) {
	registry().lock().record_timer(key, duration_ms);
}

pub fn export_metrics() -> String {
	registry().lock().export_metrics()
}

pub fn export_health() -> String {
	registry().lock().export_health()
}

pub fn set_ticks(ticks: u64) {
	let mut registry = registry().lock();
	let current = registry.counters.get("ticks").cloned().unwrap_or(0);
	if ticks > current {
		registry.inc_counter("ticks", ticks - current);
	}
}

pub fn set_avg_latency_ms(avg_ms: f32) {
	if avg_ms.is_sign_negative() {
		return;
	}
	let value = avg_ms as u64;
	registry().lock().record_timer("latence_moy_ms", value);
}

pub fn set_loop_latency_ms(latency_ms: f32) {
	if latency_ms.is_sign_negative() {
		return;
	}
	registry().lock().set_gauge("latence_boucle_ms", latency_ms as i64);
}

pub fn set_loop_latency_p95_ms(latency_ms: f32) {
	if latency_ms.is_sign_negative() {
		return;
	}
	registry().lock().set_gauge("latence_boucle_p95_ms", latency_ms as i64);
}

pub fn set_loop_latency_p99_ms(latency_ms: f32) {
	if latency_ms.is_sign_negative() {
		return;
	}
	registry().lock().set_gauge("latence_boucle_p99_ms", latency_ms as i64);
}

pub fn set_loop_jitter_ms(jitter_ms: f32) {
	if jitter_ms.is_sign_negative() {
		return;
	}
	registry().lock().set_gauge("latence_boucle_jitter_ms", jitter_ms as i64);
}

pub fn inc_errors_total() {
	registry().lock().inc_counter("errors_total", 1);
}

pub fn inc_safe_ai_actions() {
	registry().lock().inc_counter("safe_ai_actions", 1);
}

pub fn inc_ipc_drops() {
	registry().lock().inc_counter("ipc_drops", 1);
}

pub fn inc_quota_throttles() {
	registry().lock().inc_counter("quota_throttles", 1);
}
