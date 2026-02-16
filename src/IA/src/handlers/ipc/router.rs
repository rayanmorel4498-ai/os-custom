use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::prelude::String;
use sha2::{Digest, Sha256};
use spin::Mutex;
use super::contracts::{IpcCapability, IpcChannelQuota, IpcMessage, IpcTargetClass};
use crate::init::{is_locked, set_locked};
use crate::security::tls::bundle as tls_bundle;

#[derive(Clone, Copy)]
struct ChannelState {
	window_start_ms: u64,
	count: u32,
	last_nonce: u64,
}

static CHANNEL_STATE: Mutex<BTreeMap<String, ChannelState>> = Mutex::new(BTreeMap::new());
static CHANNEL_QUOTAS: Mutex<BTreeMap<String, IpcChannelQuota>> = Mutex::new(BTreeMap::new());
static CHANNEL_CAPS: Mutex<BTreeMap<String, IpcCapability>> = Mutex::new(BTreeMap::new());
static CHANNEL_REQUIRE_AUTH: Mutex<BTreeMap<String, bool>> = Mutex::new(BTreeMap::new());
static MODULE_NONCES: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

pub fn set_channel_quota(channel: &str, max_messages: u32, window_ms: u64) {
	let mut quotas = CHANNEL_QUOTAS.lock();
	quotas.insert(
		channel.into(),
		IpcChannelQuota {
			max_messages: max_messages.max(1),
			window_ms: window_ms.max(1),
		},
	);
}

pub fn set_channel_capabilities(channel: &str, caps: IpcCapability) {
	let mut map = CHANNEL_CAPS.lock();
	map.insert(channel.into(), caps);
}

pub fn set_channel_require_auth(channel: &str, required: bool) {
	let mut map = CHANNEL_REQUIRE_AUTH.lock();
	map.insert(channel.into(), required);
}

pub fn module_auth_key(module: &str) -> Result<u64, &'static str> {
	let bundle = tls_bundle::get_bundle().ok_or("ipc: missing bundle")?;
	if bundle.ticket.is_empty() {
		return Err("ipc: invalid bundle");
	}
	let mut hasher = Sha256::new();
	hasher.update(bundle.ticket.as_bytes());
	hasher.update(module.as_bytes());
	let digest = hasher.finalize();
	let mut bytes = [0u8; 8];
	bytes.copy_from_slice(&digest[..8]);
	Ok(u64::from_le_bytes(bytes))
}

pub fn next_nonce_for_module(module: &str) -> u64 {
	let mut map = MODULE_NONCES.lock();
	let entry = map.entry(module.into()).or_insert(0);
	*entry = entry.saturating_add(1);
	*entry
}

pub fn build_secure_message(module: &str, opcode: u16, payload: Vec<u8>) -> Result<IpcMessage, &'static str> {
	let nonce = next_nonce_for_module(module);
	let key = module_auth_key(module)?;
	Ok(IpcMessage {
		version: super::contracts::IPC_VERSION,
		opcode,
		nonce,
		checksum: None,
		auth_tag: None,
		payload,
	}
	.with_checksum()
	.with_auth(key))
}

	pub fn route_with_module(
		msg: &IpcMessage,
		channel: &str,
		now_ms: u64,
		module: &str,
	) -> Result<IpcTargetClass, &'static str> {
		let key = module_auth_key(module)?;
		route_with_quota(msg, channel, now_ms, Some(key))
	}

pub fn route_with_quota(
	msg: &IpcMessage,
	channel: &str,
	now_ms: u64,
	auth_key: Option<u64>,
) -> Result<IpcTargetClass, &'static str> {
	if is_locked() {
		return Err("ipc: locked");
	}
	if !tls_bundle::is_bundle_valid(now_ms) {
		set_locked(true);
		return Err("ipc: bundle expired");
	}
	msg.validate()?;
	let require_auth = {
		let map = CHANNEL_REQUIRE_AUTH.lock();
		map.get(channel).copied().unwrap_or(true)
	};
	if require_auth {
		let key = auth_key.ok_or("ipc: missing auth key")?;
		msg.validate_auth(key)?;
	}
	let quota = {
		let quotas = CHANNEL_QUOTAS.lock();
		quotas.get(channel).copied().unwrap_or(IpcChannelQuota {
			max_messages: 64,
			window_ms: 1000,
		})
	};
	let caps = {
		let map = CHANNEL_CAPS.lock();
		map.get(channel).copied().unwrap_or(IpcCapability {
			allow_core: false,
			allow_security: false,
			allow_modules: false,
			allow_storage: false,
			allow_device: false,
			allow_ui: false,
		})
	};
	let mut state_map = CHANNEL_STATE.lock();
	let state = state_map.entry(channel.into()).or_insert(ChannelState {
		window_start_ms: now_ms,
		count: 0,
		last_nonce: 0,
	});
	if msg.nonce <= state.last_nonce {
		return Err("ipc: replay detected");
	}
	if now_ms.saturating_sub(state.window_start_ms) >= quota.window_ms {
		state.window_start_ms = now_ms;
		state.count = 0;
	}
	if state.count >= quota.max_messages {
		return Err("ipc: channel quota exceeded");
	}
	state.count = state.count.saturating_add(1);
	state.last_nonce = msg.nonce;
	let target = route(msg);
	let allowed = match target {
		IpcTargetClass::Core => caps.allow_core,
		IpcTargetClass::Security => caps.allow_security,
		IpcTargetClass::Modules => caps.allow_modules,
		IpcTargetClass::Storage => caps.allow_storage,
		IpcTargetClass::Device => caps.allow_device,
		IpcTargetClass::Ui => caps.allow_ui,
	};
	if !allowed {
		return Err("ipc: capability denied");
	}
	Ok(target)
}

pub fn route(msg: &IpcMessage) -> IpcTargetClass {
	match msg.opcode {
		0..=99 => IpcTargetClass::Core,
		100..=199 => IpcTargetClass::Security,
		200..=299 => IpcTargetClass::Modules,
		300..=399 => IpcTargetClass::Storage,
		400..=499 => IpcTargetClass::Device,
		_ => IpcTargetClass::Ui,
	}
}
