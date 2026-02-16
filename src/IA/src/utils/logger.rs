use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use spin::{Mutex, Once};
use crate::time;
use crate::utils::error::ErrorCode;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
	Error,
	Warn,
	Info,
}

#[derive(Clone)]
pub struct LogEntry {
	pub level: LogLevel,
	pub module: String,
	pub code: ErrorCode,
	pub timestamp_ms: u64,
	pub context: String,
}

pub struct Logger {
	entries: VecDeque<LogEntry>,
	max_entries: usize,
}

impl Logger {
	pub fn new() -> Self {
		Logger {
			entries: VecDeque::new(),
			max_entries: 256,
		}
	}

	pub fn log(&mut self, level: LogLevel, module: &str, code: ErrorCode, context: &str) {
		if self.entries.len() >= self.max_entries {
			self.entries.pop_front();
		}
		self.entries.push_back(LogEntry {
			level,
			module: module.to_string(),
			code,
			timestamp_ms: time::now_ms(),
			context: context.to_string(),
		});
	}

	pub fn export_kv(&self) -> String {
		let mut out = String::new();
		for (idx, entry) in self.entries.iter().enumerate() {
			let level = match entry.level {
				LogLevel::Error => "error",
				LogLevel::Warn => "warn",
				LogLevel::Info => "info",
			};
			out.push_str(&alloc::format!(
				"log{}.level={},log{}.module={},log{}.code={},log{}.ts={},log{}.ctx={};",
				idx,
				level,
				idx,
				entry.module,
				idx,
				entry.code.as_str(),
				idx,
				entry.timestamp_ms,
				idx,
				entry.context
			));
		}
		out
	}
}

static LOGGER: Once<Mutex<Logger>> = Once::new();

fn logger() -> &'static Mutex<Logger> {
	LOGGER.call_once(|| Mutex::new(Logger::new()))
}

pub fn error(module: &str, code: ErrorCode, context: &str) {
	logger().lock().log(LogLevel::Error, module, code, context);
}

pub fn warn(module: &str, code: ErrorCode, context: &str) {
	logger().lock().log(LogLevel::Warn, module, code, context);
}

pub fn info(module: &str, code: ErrorCode, context: &str) {
	logger().lock().log(LogLevel::Info, module, code, context);
}

pub fn export_logs() -> String {
	logger().lock().export_kv()
}
