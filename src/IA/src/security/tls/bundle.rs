use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};
use crate::utils::error::ErrorCode;
use crate::utils::logger;
use crate::security::tls::tls_client::TLSClient;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct TlsBundle {
	pub ticket: String,
	pub routes: Vec<String>,
	pub expires_at_ms: u64,
	pub generation: u64,
	pub epoch_ms: u64,
	pub signature: Vec<u8>,
}

static BUNDLES: Once<Mutex<BTreeMap<String, TlsBundle>>> = Once::new();
static CLIENT: Once<Mutex<Option<TLSClient>>> = Once::new();
static PENDING: Once<Mutex<Option<TlsBundle>>> = Once::new();
static PENDING_MODULE: Once<Mutex<Option<String>>> = Once::new();
static GEN: AtomicU64 = AtomicU64::new(1);

fn bundle_store() -> &'static Mutex<BTreeMap<String, TlsBundle>> {
	BUNDLES.call_once(|| Mutex::new(BTreeMap::new()))
}

fn client_store() -> &'static Mutex<Option<TLSClient>> {
	CLIENT.call_once(|| Mutex::new(None))
}

fn pending_store() -> &'static Mutex<Option<TlsBundle>> {
	PENDING.call_once(|| Mutex::new(None))
}

fn pending_module_store() -> &'static Mutex<Option<String>> {
	PENDING_MODULE.call_once(|| Mutex::new(None))
}

fn verify_signature(secret: &[u8], module: &str, bundle: &TlsBundle) -> bool {
	let mut hasher = Sha256::new();
	hasher.update(secret);
	hasher.update(module.as_bytes());
	hasher.update(bundle.ticket.as_bytes());
	hasher.update(bundle.routes.join(",").as_bytes());
	hasher.update(bundle.expires_at_ms.to_le_bytes());
	hasher.update(bundle.generation.to_le_bytes());
	hasher.update(bundle.epoch_ms.to_le_bytes());
	let computed = hasher.finalize();
	computed.as_slice() == bundle.signature.as_slice()
}

fn hex_to_bytes(input: &str) -> Option<Vec<u8>> {
	let bytes = input.as_bytes();
	if bytes.len() % 2 != 0 {
		return None;
	}
	let mut out = Vec::with_capacity(bytes.len() / 2);
	let mut i = 0;
	while i < bytes.len() {
		let hi = (bytes[i] as char).to_digit(16)? as u8;
		let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
		out.push((hi << 4) | lo);
		i += 2;
	}
	Some(out)
}

pub fn set_client(client: TLSClient) {
	*client_store().lock() = Some(client);
}

pub fn client() -> Option<TLSClient> {
	client_store().lock().clone()
}

pub fn set_pending_module(module: &str) -> Result<(), ErrorCode> {
	let mut guard = pending_module_store().lock();
	if guard.is_some() {
		return Err(ErrorCode::ErrBusy);
	}
	*guard = Some(module.to_string());
	Ok(())
}

pub fn set_pending_bundle(bundle: TlsBundle) {
	*pending_store().lock() = Some(bundle);
}

const EXPECTED_BUNDLE_FIELDS: [&str; 6] = [
	"ticket",
	"routes",
	"expires_at_ms",
	"generation",
	"epoch_ms",
	"signature",
];

const MAX_EPOCH_SKEW_MS: u64 = 120_000;

pub fn parse_bundle_payload(text: &str) -> Result<TlsBundle, ErrorCode> {
	let mut map: BTreeMap<String, String> = BTreeMap::new();
	for raw in text.split(';') {
		let part = raw.trim();
		if part.is_empty() {
			continue;
		}
		let mut entry = part.splitn(2, '=');
		let key = entry.next().unwrap_or("").trim();
		let value = entry.next().ok_or(ErrorCode::ErrProtocol)?.trim();
		if key.is_empty() {
			return Err(ErrorCode::ErrProtocol);
		}
		if value.is_empty() {
			return Err(ErrorCode::ErrInvalidInput);
		}
		if !EXPECTED_BUNDLE_FIELDS.contains(&key) {
			return Err(ErrorCode::ErrProtocol);
		}
		if map.contains_key(key) {
			return Err(ErrorCode::ErrProtocol);
		}
		map.insert(String::from(key), String::from(value));
	}
	if map.len() != EXPECTED_BUNDLE_FIELDS.len() {
		return Err(ErrorCode::ErrProtocol);
	}
	let ticket = map.remove("ticket").unwrap();
	let routes_field = map.remove("routes").unwrap();
	let expires_at_ms = map
		.remove("expires_at_ms")
		.unwrap()
		.parse::<u64>()
		.map_err(|_| ErrorCode::ErrInvalidInput)?;
	let generation = map
		.remove("generation")
		.unwrap()
		.parse::<u64>()
		.map_err(|_| ErrorCode::ErrInvalidInput)?;
	let epoch_ms = map
		.remove("epoch_ms")
		.unwrap()
		.parse::<u64>()
		.map_err(|_| ErrorCode::ErrInvalidInput)?;
	let signature_hex = map.remove("signature").unwrap();
	let signature = hex_to_bytes(&signature_hex).ok_or(ErrorCode::ErrInvalidInput)?;
	if ticket.is_empty() || expires_at_ms == 0 {
		return Err(ErrorCode::ErrInvalidInput);
	}
	let routes: Vec<String> = routes_field
		.split(',')
		.map(str::trim)
		.filter(|r| !r.is_empty())
		.map(String::from)
		.collect();
	if routes.is_empty() {
		return Err(ErrorCode::ErrInvalidInput);
	}
	Ok(TlsBundle {
		ticket,
		routes,
		expires_at_ms,
		generation,
		epoch_ms,
		signature,
	})
}

pub fn handle_bundle_payload(payload: &[u8]) -> Result<(), ErrorCode> {
	let client = client_store().lock().clone().ok_or(ErrorCode::ErrUnavailable)?;
	if !client.is_authenticated() {
		logger::error("tls", ErrorCode::ErrUnauthorized, "tls client unauthenticated");
		return Err(ErrorCode::ErrUnauthorized);
	}
	if pending_module_store().lock().is_none() {
		logger::error("tls", ErrorCode::ErrUnauthorized, "bundle without pending module");
		return Err(ErrorCode::ErrUnauthorized);
	}
	let text = core::str::from_utf8(payload).map_err(|_| ErrorCode::ErrProtocol)?;
	let bundle = parse_bundle_payload(text)?;
	set_pending_bundle(bundle);
	Ok(())
}

pub fn receive_tls_bundle(payload: &[u8]) -> Result<(), ErrorCode> {
	handle_bundle_payload(payload)
}

pub(crate) fn store_bundle(bundle: TlsBundle) {
	store_bundle_for("ia", bundle);
}

pub(crate) fn store_bundle_for(module: &str, bundle: TlsBundle) {
	bundle_store().lock().insert(module.to_string(), bundle);
}

pub fn get_bundle() -> Option<TlsBundle> {
	get_bundle_for("ia")
}

pub fn get_bundle_for(module: &str) -> Option<TlsBundle> {
	bundle_store().lock().get(module).cloned()
}

pub fn is_bundle_valid(now_ms: u64) -> bool {
	is_bundle_valid_for("ia", now_ms)
}

pub fn is_bundle_valid_for(module: &str, now_ms: u64) -> bool {
	bundle_store()
		.lock()
		.get(module)
		.map(|b| !b.ticket.is_empty() && b.expires_at_ms > now_ms)
		.unwrap_or(false)
}

pub fn handshake_and_store(now_ms: u64) -> Result<(), ErrorCode> {
	handshake_and_store_for("ia", now_ms)
}

pub fn handshake_and_store_for(module: &str, now_ms: u64) -> Result<(), ErrorCode> {
	handshake_and_store_for_with_ttl(module, now_ms, None)
}

pub fn handshake_and_store_for_with_ttl(
	module: &str,
	now_ms: u64,
	ttl_secs: Option<u64>,
) -> Result<(), ErrorCode> {
	let client = client_store().lock().clone().ok_or(ErrorCode::ErrUnavailable)?;
	if !client.is_authenticated() {
		logger::error("tls", ErrorCode::ErrUnauthorized, "tls client unauthenticated");
		return Err(ErrorCode::ErrUnauthorized);
	}
	set_pending_module(module)?;
	let result = (|| {
		let request = if let Some(ttl) = ttl_secs {
			alloc::format!("bundle_request;module={module};ttl_secs={ttl}")
		} else {
			alloc::format!("bundle_request;module={module}")
		};
		let _ = client.send_tls_payload(request.into_bytes(), 1);
		let mut bundle = pending_store().lock().take().ok_or(ErrorCode::ErrUnavailable)?;
		let secret = client.secret_for_component(module).ok_or(ErrorCode::ErrUnauthorized)?;
		if bundle.ticket.is_empty() {
			return Err(ErrorCode::ErrUnauthorized);
		}
		if bundle.routes.is_empty() {
			return Err(ErrorCode::ErrInvalidInput);
		}
		if bundle.epoch_ms == 0 {
			return Err(ErrorCode::ErrInvalidInput);
		}
		if now_ms < bundle.epoch_ms || now_ms.saturating_sub(bundle.epoch_ms) > MAX_EPOCH_SKEW_MS {
			return Err(ErrorCode::ErrInvalidInput);
		}
		if bundle.expires_at_ms <= now_ms {
			return Err(ErrorCode::ErrInvalidInput);
		}
		if !verify_signature(&secret, module, &bundle) {
			logger::error("tls", ErrorCode::ErrUnauthorized, "bundle signature invalid");
			return Err(ErrorCode::ErrUnauthorized);
		}
		if bundle.generation == 0 {
			bundle.generation = GEN.fetch_add(1, Ordering::Relaxed);
		}
		store_bundle_for(module, bundle);
		Ok(())
	})();
	let mut pending = pending_module_store().lock();
	*pending = None;
	result
}

pub fn refresh_bundle(now_ms: u64) -> Result<(), ErrorCode> {
	refresh_bundle_for("ia", now_ms)
}

pub fn refresh_bundle_for(module: &str, now_ms: u64) -> Result<(), ErrorCode> {
	handshake_and_store_for(module, now_ms)
}

pub fn refresh_bundle_for_with_ttl(
	module: &str,
	now_ms: u64,
	ttl_secs: Option<u64>,
) -> Result<(), ErrorCode> {
	handshake_and_store_for_with_ttl(module, now_ms, ttl_secs)
}

pub fn refresh_if_needed(now_ms: u64, refresh_window_ms: u64) -> Result<bool, ErrorCode> {
	refresh_if_needed_for("ia", now_ms, refresh_window_ms)
}

pub fn refresh_if_needed_for(
	module: &str,
	now_ms: u64,
	refresh_window_ms: u64,
) -> Result<bool, ErrorCode> {
	refresh_if_needed_for_with_ttl(module, now_ms, refresh_window_ms, None)
}

pub fn refresh_if_needed_for_with_ttl(
	module: &str,
	now_ms: u64,
	refresh_window_ms: u64,
	ttl_secs: Option<u64>,
) -> Result<bool, ErrorCode> {
	let refresh_window_ms = refresh_window_ms.max(1_000);
	let needs = bundle_store()
		.lock()
		.get(module)
		.map(|b| b.expires_at_ms.saturating_sub(now_ms) <= refresh_window_ms)
		.unwrap_or(true);
	if !needs {
		return Ok(false);
	}
	handshake_and_store_for_with_ttl(module, now_ms, ttl_secs)?;
	Ok(true)
}
