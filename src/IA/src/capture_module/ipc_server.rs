use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use crate::security::tls::bundle as tls_bundle;
use crate::utils::error::ErrorCode;
use sha2::{Digest, Sha256};
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_EPOCH_SKEW_MS: u64 = 120_000;
const EPH_TTL_MS: u64 = 30_000;
static EPH_COUNTER: AtomicU64 = AtomicU64::new(1);
static EPH_HANDLES: spin::Once<spin::Mutex<BTreeMap<String, u64>>> = spin::Once::new();

pub struct CaptureIpcServer {
}

pub fn handle_request_bytes(msg: &[u8], now_ms: u64) -> Vec<u8> {
	CaptureIpcServer::new().handle_request_bytes(msg, now_ms)
}

impl CaptureIpcServer {
	pub fn new() -> Self {
		CaptureIpcServer {}
	}

	pub fn handle_request_bytes(&self, msg: &[u8], now_ms: u64) -> Vec<u8> {
		let response = match IncomingRequest::from_bytes(msg) {
			Ok(req) => self.handle_request(req, now_ms),
			Err(err) => CaptureResponse::cap_err(0, err),
		};
		response.into_bytes()
	}

	fn handle_request(&self, req: IncomingRequest, now_ms: u64) -> CaptureResponse {
		match req {
			IncomingRequest::Eph(req) => self.handle_eph(req, now_ms),
			IncomingRequest::Cap(req) => self.handle_cap(req, now_ms),
		}
	}

	fn handle_eph(&self, req: EphRequest, now_ms: u64) -> CaptureResponse {
		if req.version != 1 || req.nonce == 0 {
			return CaptureResponse::eph_err(req.nonce, "bad_request".into());
		}
		if !req.verify_signature() {
			return CaptureResponse::eph_err(req.nonce, "bad_signature".into());
		}
		let handle = format!("eph-{}", EPH_COUNTER.fetch_add(1, Ordering::Relaxed));
		let exp = now_ms.saturating_add(EPH_TTL_MS);
		let store = eph_store();
		store.lock().insert(handle.clone(), exp);
		CaptureResponse::eph_ok(req.nonce, handle, EPH_TTL_MS)
	}

	fn handle_cap(&self, req: CapRequest, now_ms: u64) -> CaptureResponse {
		if req.version != 1 {
			return CaptureResponse::cap_err(req.nonce, "capture: bad version".into());
		}
		if req.op != "audio" {
			return CaptureResponse::cap_err(req.nonce, "capture: unsupported op".into());
		}
		if !req.verify_signature() {
			return CaptureResponse::cap_err(req.nonce, "capture: bad signature".into());
		}
		if !consume_handle(&req.handle, now_ms) {
			return CaptureResponse::cap_err(req.nonce, "capture: invalid handle".into());
		}
		let bundle = match tls_bundle::parse_bundle_payload(&req.bundle_payload) {
			Ok(b) => b,
			Err(_) => return CaptureResponse::cap_err(req.nonce, "capture: invalid bundle".into()),
		};
		if !verify_bundle(now_ms, &bundle) {
			return CaptureResponse::cap_err(req.nonce, "capture: bundle expired".into());
		}
		let len = req.len as usize;
		let payload = generate_audio_payload(len, req.nonce, &bundle.ticket);
		CaptureResponse::cap_ok(req.nonce, payload)
	}
}

enum IncomingRequest {
	Eph(EphRequest),
	Cap(CapRequest),
}

impl IncomingRequest {
	fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
		let text = core::str::from_utf8(bytes).map_err(|_| "capture: request utf8")?;
		if text.starts_with("EPH_REQ") {
			return EphRequest::from_text(text).map(IncomingRequest::Eph);
		}
		if text.starts_with("CAP_REQ") {
			return CapRequest::from_text(text).map(IncomingRequest::Cap);
		}
		Err("capture: unknown request".into())
	}
}

struct EphRequest {
	version: u32,
	nonce: u64,
	signature: String,
}

impl EphRequest {
	fn from_text(text: &str) -> Result<Self, String> {
		let mut version = 0u32;
		let mut nonce = 0u64;
		let mut signature = String::new();
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
				"nonce" => nonce = value.parse::<u64>().unwrap_or(0),
				"sig" => signature = value.to_string(),
				_ => {}
			}
		}
		if signature.is_empty() {
			return Err("capture: missing signature".into());
		}
		Ok(EphRequest { version, nonce, signature })
	}

	fn verify_signature(&self) -> bool {
		let Some(secret) = capture_secret("ia") else {
			return false;
		};
		let mut hasher = Sha256::new();
		hasher.update(&secret);
		hasher.update("EPH_REQ".as_bytes());
		hasher.update(self.nonce.to_le_bytes());
		let digest = hasher.finalize();
		let expected = hex_encode(digest.as_slice());
		expected == self.signature
	}
}

struct CapRequest {
	version: u32,
	op: String,
	nonce: u64,
	len: u32,
	bundle_hex: String,
	bundle_payload: String,
	handle: String,
	signature: String,
}

impl CapRequest {
	fn from_text(text: &str) -> Result<Self, String> {
		let mut version = 0u32;
		let mut op = String::new();
		let mut nonce = 0u64;
		let mut len = 0u32;
		let mut bundle_hex = String::new();
		let mut bundle_payload = String::new();
		let mut handle = String::new();
		let mut signature = String::new();
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
				"nonce" => nonce = value.parse::<u64>().unwrap_or(0),
				"len" => len = value.parse::<u32>().unwrap_or(0),
				"bundle" => {
					bundle_hex = value.to_string();
					let bytes = hex_decode(value).ok_or("capture: bad bundle hex")?;
					bundle_payload = core::str::from_utf8(&bytes)
						.map_err(|_| "capture: bundle utf8")?
						.to_string();
				}
			"handle" => handle = value.to_string(),
			"sig" => signature = value.to_string(),
				_ => {}
			}
		}
	if op.is_empty() || bundle_payload.is_empty() || handle.is_empty() || signature.is_empty() {
			return Err("capture: missing request fields".into());
		}
		Ok(CapRequest {
			version,
			op,
			nonce,
			len,
			bundle_hex,
			bundle_payload,
		handle,
			signature,
		})
	}

	fn verify_signature(&self) -> bool {
		let Some(secret) = capture_secret("ia") else {
			return false;
		};
		let mut hasher = Sha256::new();
		hasher.update(&secret);
		hasher.update("CAP_REQ".as_bytes());
		hasher.update(self.op.as_bytes());
		hasher.update(self.nonce.to_le_bytes());
		hasher.update(self.len.to_le_bytes());
		hasher.update(self.bundle_hex.as_bytes());
		hasher.update(self.handle.as_bytes());
		let digest = hasher.finalize();
		let expected = hex_encode(digest.as_slice());
		expected == self.signature
	}
}

#[derive(Clone)]
struct CaptureResponse {
	status: String,
	nonce: u64,
	len: u32,
	signature: String,
	payload: Option<Vec<u8>>,
	error_code: Option<String>,
}

impl CaptureResponse {
	fn cap_ok(nonce: u64, payload: Vec<u8>) -> Self {
		let len = payload.len() as u32;
		let signature = sign_response("ok", nonce, len, Some(&payload), None);
		CaptureResponse {
			status: "ok".into(),
			nonce,
			len,
			signature,
			payload: Some(payload),
			error_code: None,
		}
	}

	fn cap_err(nonce: u64, code: String) -> Self {
		let signature = sign_response("err", nonce, 0, None, Some(&code));
		CaptureResponse {
			status: "err".into(),
			nonce,
			len: 0,
			signature,
			payload: None,
			error_code: Some(code),
		}
	}

	fn eph_ok(nonce: u64, handle: String, ttl_ms: u64) -> Self {
		let signature = sign_eph_response("EPH_OK", nonce, Some((&handle, ttl_ms)), None);
		CaptureResponse {
			status: "EPH_OK".into(),
			nonce,
			len: 0,
			signature,
			payload: Some(handle.into_bytes()),
			error_code: Some(format!("ttl={}", ttl_ms)),
		}
	}

	fn eph_err(nonce: u64, code: String) -> Self {
		let signature = sign_eph_response("EPH_ERR", nonce, None, Some(&code));
		CaptureResponse {
			status: "EPH_ERR".into(),
			nonce,
			len: 0,
			signature,
			payload: None,
			error_code: Some(code),
		}
	}

	fn into_bytes(self) -> Vec<u8> {
		match self.status.as_str() {
			"EPH_OK" => {
				let handle = self.payload.unwrap_or_default();
				let ttl = self.error_code.unwrap_or_default();
				format!(
					"EPH_OK;v=1;nonce={};handle={};{};sig={}",
					self.nonce,
					String::from_utf8(handle).unwrap_or_default(),
					ttl,
					self.signature
				)
				.into_bytes()
			}
			"EPH_ERR" => {
				let code = self.error_code.unwrap_or_default();
				format!("EPH_ERR;v=1;nonce={};code={};sig={}", self.nonce, code, self.signature)
					.into_bytes()
			}
			_ => {
				let mut text = format!(
					"CAP_RESP;v=1;status={};nonce={};len={};sig={}",
					self.status, self.nonce, self.len, self.signature
				);
				if let Some(payload) = self.payload {
					text.push_str(";payload=");
					text.push_str(&hex_encode(&payload));
				}
				if let Some(code) = self.error_code {
					text.push_str(";code=");
					text.push_str(&code);
				}
				text.into_bytes()
			}
		}
	}
}

fn verify_bundle(now_ms: u64, bundle: &tls_bundle::TlsBundle) -> bool {
	if bundle.ticket.is_empty() || bundle.routes.is_empty() {
		return false;
	}
	if bundle.epoch_ms == 0 || bundle.expires_at_ms <= now_ms {
		return false;
	}
	if now_ms < bundle.epoch_ms || now_ms.saturating_sub(bundle.epoch_ms) > MAX_EPOCH_SKEW_MS {
		return false;
	}
	let Some(secret) = capture_secret("capture_module") else {
		return false;
	};
	let mut hasher = Sha256::new();
	hasher.update(&secret);
	hasher.update("capture_module".as_bytes());
	hasher.update(bundle.ticket.as_bytes());
	hasher.update(bundle.routes.join(",").as_bytes());
	hasher.update(bundle.expires_at_ms.to_le_bytes());
	hasher.update(bundle.generation.to_le_bytes());
	hasher.update(bundle.epoch_ms.to_le_bytes());
	let digest = hasher.finalize();
	hex_encode(digest.as_slice()) == hex_encode(&bundle.signature)
}

fn generate_audio_payload(len: usize, nonce: u64, ticket: &str) -> Vec<u8> {
	let mut out = Vec::with_capacity(len);
	let ticket_bytes = ticket.as_bytes();
	for i in 0..len {
		let tb = ticket_bytes.get(i % ticket_bytes.len().max(1)).copied().unwrap_or(0);
		let v = (tb as u64).wrapping_add(nonce).wrapping_add(i as u64);
		out.push((v & 0xff) as u8);
	}
	out
}


fn sign_response(status: &str, nonce: u64, len: u32, payload: Option<&[u8]>, code: Option<&str>) -> String {
	let Some(secret) = capture_secret("capture_module") else {
		return "".into();
	};
	let mut hasher = Sha256::new();
	hasher.update(&secret);
	hasher.update(status.as_bytes());
	hasher.update(nonce.to_le_bytes());
	hasher.update(len.to_le_bytes());
	if let Some(payload) = payload {
		hasher.update(payload);
	}
	if let Some(code) = code {
		hasher.update(code.as_bytes());
	}
	let digest = hasher.finalize();
	hex_encode(digest.as_slice())
}

fn sign_eph_response(status: &str, nonce: u64, handle_ttl: Option<(&str, u64)>, code: Option<&str>) -> String {
	let Some(secret) = capture_secret("ia") else {
		return "".into();
	};
	let mut hasher = Sha256::new();
	hasher.update(&secret);
	hasher.update(status.as_bytes());
	hasher.update(nonce.to_le_bytes());
	if let Some((handle, ttl_ms)) = handle_ttl {
		hasher.update(handle.as_bytes());
		hasher.update(ttl_ms.to_le_bytes());
	}
	if let Some(code) = code {
		hasher.update(code.as_bytes());
	}
	let digest = hasher.finalize();
	hex_encode(digest.as_slice())
}

fn eph_store() -> &'static spin::Mutex<BTreeMap<String, u64>> {
	EPH_HANDLES.call_once(|| spin::Mutex::new(BTreeMap::new()))
}

fn consume_handle(handle: &str, now_ms: u64) -> bool {
	let store = eph_store();
	let mut map = store.lock();
	if let Some(exp) = map.get(handle).copied() {
		if exp <= now_ms {
			map.remove(handle);
			return false;
		}
		map.remove(handle);
		return true;
	}
	false
}

fn capture_secret(component: &str) -> Option<Vec<u8>> {
	let client = tls_bundle::client()?;
	client.secret_for_component(component)
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

fn hex_decode(input: &str) -> Option<Vec<u8>> {
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

fn format_error(err: ErrorCode) -> String {
	format!("capture: {err:?}")
}

impl From<ErrorCode> for String {
	fn from(err: ErrorCode) -> Self {
		format_error(err)
	}
}
