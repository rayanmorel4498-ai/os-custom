use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

use crate::io::ipc_socket;
use crate::security::tls::bundle as tls_bundle;
use crate::time;

static NONCE: AtomicU64 = AtomicU64::new(1);
const TLS_SECONDARY_SOCKET_PATH: &str = "/tmp/tls_secondary_loop.sock";
const TLS_REPLY_PREFIX: &str = "/tmp/tls_secondary_loop.reply.";
const RESPONSE_SPIN_LIMIT: u32 = 50_000;

pub struct IaCaptureClient;

impl IaCaptureClient {
	pub fn new() -> Self {
		IaCaptureClient
	}

	pub fn capture_audio(&self, len: usize) -> Result<Vec<u8>, String> {
		self.capture_with_op("audio", len)
	}

	pub fn capture_video(&self, len: usize) -> Result<Vec<u8>, String> {
		self.capture_with_op("video", len)
	}

	pub fn capture_screen(&self, len: usize) -> Result<Vec<u8>, String> {
		self.capture_with_op("screen", len)
	}

	pub fn capture_camera(&self, len: usize) -> Result<Vec<u8>, String> {
		self.capture_with_op("camera", len)
	}

	pub fn capture_depth(&self, len: usize) -> Result<Vec<u8>, String> {
		self.capture_with_op("depth", len)
	}

	fn capture_with_op(&self, op: &str, len: usize) -> Result<Vec<u8>, String> {
		let _ = len;
		let now_ms = time::now_ms();
		self.ensure_bundle(now_ms)?;
		let (ia_id, pool_id) = get_ids()?;
		let eph_nonce = NONCE.fetch_add(1, Ordering::Relaxed);
		let handle = request_ephemeral_handle(op, eph_nonce, ia_id, pool_id)?;
		let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
		let bundle = tls_bundle::get_bundle_for("ia").ok_or_else(|| "capture: missing bundle".to_string())?;
		let bundle_payload = serialize_bundle(&bundle);
		let bundle_b64 = base64_encode_no_pad(bundle_payload.as_bytes());
		let signature = sign_capture_request(op, nonce, ia_id, pool_id, &handle, &bundle_b64)?;
		let request = build_capture_request(op, nonce, ia_id, pool_id, &handle, &bundle_b64, &signature);
		let response = send_tls_secondary_request(request, nonce)?;
		parse_tls_capture_response(response)
	}

	fn ensure_bundle(&self, now_ms: u64) -> Result<(), String> {
		if tls_bundle::is_bundle_valid_for("ia", now_ms) {
			return Ok(());
		}
		tls_bundle::handshake_and_store_for("ia", now_ms)
			.map_err(|_| "capture: tls bundle request failed".to_string())
	}
}


fn build_capture_request(
	op: &str,
	nonce: u64,
	ia_id: u64,
	pool_id: u32,
	handle: &str,
	bundle_b64: &str,
	signature: &str,
) -> String {
	let ia_id_hex = hex_u64(ia_id);
	let pool_id_hex = hex_u32(pool_id);
	let nonce_hex = hex_u64(nonce);
	format!(
		"CAP_REQ;v=1;api=capture;op={};mode=run;first_run=1;ia_id={};pool_id={};handle={};bundle={};nonce={};sig={}",
		op,
		ia_id_hex,
		pool_id_hex,
		handle,
		bundle_b64,
		nonce_hex,
		signature
	)
}

fn sign_capture_request(
	op: &str,
	nonce: u64,
	ia_id: u64,
	pool_id: u32,
	handle: &str,
	bundle_b64: &str,
) -> Result<String, String> {
	let secret = tls_bundle::client()
		.and_then(|client| client.secret_for_component("ia"))
		.ok_or_else(|| "capture: missing ia secret".to_string())?;
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
	hasher.update(&secret);
	hasher.update(base.as_bytes());
	let digest = hasher.finalize();
	Ok(hex_encode(digest.as_slice()))
}

fn request_ephemeral_handle(op: &str, nonce: u64, ia_id: u64, pool_id: u32) -> Result<String, String> {
	let signature = sign_eph_request(op, nonce, ia_id, pool_id)?;
	let request = build_eph_request(op, nonce, ia_id, pool_id, &signature);
	let response = send_tls_secondary_request(request, nonce)?;
	parse_eph_response(response)
}

fn build_eph_request(op: &str, nonce: u64, ia_id: u64, pool_id: u32, signature: &str) -> String {
	format!(
		"EPH_REQ;v=1;api=capture;op={};mode=run;first_run=1;ia_id={};pool_id={};nonce={};sig={}",
		op,
		hex_u64(ia_id),
		hex_u32(pool_id),
		hex_u64(nonce),
		signature
	)
}

fn sign_eph_request(op: &str, nonce: u64, ia_id: u64, pool_id: u32) -> Result<String, String> {
	let secret = tls_bundle::client()
		.and_then(|client| client.secret_for_component("ia"))
		.ok_or_else(|| "capture: missing ia secret".to_string())?;
	let base = format!(
		"EPH_REQ;v=1;api=capture;op={};mode=run;first_run=1;ia_id={};pool_id={};nonce={}",
		op,
		hex_u64(ia_id),
		hex_u32(pool_id),
		hex_u64(nonce)
	);
	let mut hasher = Sha256::new();
	hasher.update(&secret);
	hasher.update(base.as_bytes());
	let digest = hasher.finalize();
	Ok(hex_encode(digest.as_slice()))
}

fn parse_eph_response(bytes: Vec<u8>) -> Result<String, String> {
	let text = core::str::from_utf8(&bytes).map_err(|_| "capture: eph utf8".to_string())?;
	if text.starts_with("EPH_ERR") {
		return Err("capture: eph error".into());
	}
	let mut handle = String::new();
	let mut signature = String::new();
	let mut version = 0u32;
	for part in text.split(';') {
		if part.is_empty() {
			continue;
		}
		let mut kv = part.splitn(2, '=');
		let key = kv.next().unwrap_or("");
		let value = kv.next().unwrap_or("");
		match key {
			"EPH_OK" => {}
			"v" => version = value.parse::<u32>().unwrap_or(0),
			"handle" => handle = value.to_string(),
			"sig" => signature = value.to_string(),
			_ => {}
		}
	}
	if version != 1 {
		return Err("capture: eph bad version".into());
	}
	if signature.is_empty() {
		return Err("capture: eph missing signature".into());
	}
	if !verify_eph_response_signature(&handle, &signature) {
		return Err("capture: eph bad signature".into());
	}
	if handle.is_empty() {
		return Err("capture: eph missing handle".into());
	}
	Ok(handle)
}

fn verify_eph_response_signature(handle: &str, signature: &str) -> bool {
	let mut hasher = Sha256::new();
	hasher.update(format!("EPH_OK;v=1;handle={}", handle).as_bytes());
	let digest = hasher.finalize();
	hex_encode(digest.as_slice()) == signature
}

fn send_tls_secondary_request(request: String, nonce: u64) -> Result<Vec<u8>, String> {
	let reply_path = format!("{}{}", TLS_REPLY_PREFIX, nonce);
	let payload = request.into_bytes();
	let _ = reply_path;
	ipc_socket::send(TLS_SECONDARY_SOCKET_PATH, payload)?;
	let mut spins = 0u32;
	loop {
		if let Some(bytes) = ipc_socket::recv(&format!("{}{}", TLS_REPLY_PREFIX, nonce)) {
			return Ok(bytes);
		}
		spins = spins.saturating_add(1);
		if spins >= RESPONSE_SPIN_LIMIT {
			return Err("capture: tls response timeout".into());
		}
		core::hint::spin_loop();
	}
}

fn parse_tls_capture_response(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
	let text = core::str::from_utf8(&bytes).map_err(|_| "capture: tls response utf8".to_string())?;
	if text.starts_with("CAP_ERR") {
		return Err("capture: tls error".into());
	}
	let mut resp_b64 = String::new();
	let mut signature = String::new();
	let mut version = 0u32;
	for part in text.split(';') {
		if part.is_empty() {
			continue;
		}
		let mut kv = part.splitn(2, '=');
		let key = kv.next().unwrap_or("");
		let value = kv.next().unwrap_or("");
		match key {
			"CAP_OK" => {}
			"v" => version = value.parse::<u32>().unwrap_or(0),
			"resp" => resp_b64 = value.to_string(),
			"sig" => signature = value.to_string(),
			_ => {}
		}
	}
	if version != 1 {
		return Err("capture: tls bad version".into());
	}
	if resp_b64.is_empty() || signature.is_empty() {
		return Err("capture: tls missing fields".into());
	}
	if !verify_tls_cap_ok_signature(&resp_b64, &signature) {
		return Err("capture: tls bad signature".into());
	}
	let decoded = base64_decode_no_pad(&resp_b64).ok_or_else(|| "capture: tls bad resp b64".to_string())?;
	parse_capture_response(decoded)
}

fn verify_tls_cap_ok_signature(resp_b64: &str, signature: &str) -> bool {
	let mut hasher = Sha256::new();
	hasher.update(format!("CAP_OK;v=1;resp={}", resp_b64).as_bytes());
	let digest = hasher.finalize();
	hex_encode(digest.as_slice()) == signature
}

fn parse_capture_response(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
	let text = core::str::from_utf8(&bytes).map_err(|_| "capture: response utf8".to_string())?;
	let mut status = String::new();
	let mut nonce = 0u64;
	let mut len = 0u32;
	let mut signature = String::new();
	let mut payload: Option<Vec<u8>> = None;
	let mut code: Option<String> = None;
	let mut version = 0u32;
	for part in text.split(';') {
		if part.is_empty() {
			continue;
		}
		let mut kv = part.splitn(2, '=');
		let key = kv.next().unwrap_or("");
		let value = kv.next().unwrap_or("");
		match key {
			"CAP_RESP" => {}
			"status" => status = value.to_string(),
			"v" => version = value.parse::<u32>().unwrap_or(0),
			"nonce" => nonce = value.parse::<u64>().unwrap_or(0),
			"len" => len = value.parse::<u32>().unwrap_or(0),
			"sig" => signature = value.to_string(),
			"payload" => payload = hex_decode(value),
			"code" => code = Some(value.to_string()),
			_ => {}
		}
	}
	if version != 1 {
		return Err("capture: bad version".into());
	}
	if signature.is_empty() {
		return Err("capture: missing signature".into());
	}
	if !verify_capture_response_signature(&status, nonce, len, payload.as_deref(), code.as_deref(), &signature) {
		return Err("capture: bad signature".into());
	}
	if status == "err" {
		return Err(code.unwrap_or_else(|| "capture: error".into()));
	}
	let data = payload.ok_or_else(|| "capture: missing payload".to_string())?;
	if data.len() != len as usize {
		return Err("capture: payload length mismatch".into());
	}
	Ok(data)
}

fn verify_capture_response_signature(
	status: &str,
	nonce: u64,
	len: u32,
	payload: Option<&[u8]>,
	code: Option<&str>,
	signature: &str,
) -> bool {
	let Some(secret) = tls_bundle::client().and_then(|client| client.secret_for_component("capture_module")) else {
		return false;
	};
	let mut hasher = Sha256::new();
	hasher.update(&secret);
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
	hex_encode(digest.as_slice()) == signature
}

fn get_ids() -> Result<(u64, u32), String> {
	let client = tls_bundle::client().ok_or_else(|| "capture: tls client unavailable".to_string())?;
	let ia_id = client.ia_id().ok_or_else(|| "capture: ia_id missing".to_string())?;
	let pool_id = client.pool_id().ok_or_else(|| "capture: pool_id missing".to_string())?;
	Ok((ia_id, pool_id))
}

fn serialize_bundle(bundle: &tls_bundle::TlsBundle) -> String {
	let routes = bundle.routes.join(",");
	let signature_hex = hex_encode(&bundle.signature);
	format!(
		"ticket={};routes={};expires_at_ms={};generation={};epoch_ms={};signature={}",
		bundle.ticket,
		routes,
		bundle.expires_at_ms,
		bundle.generation,
		bundle.epoch_ms,
		signature_hex
	)
}

fn hex_u64(value: u64) -> String {
	format!("{:032x}", value)
}

fn hex_u32(value: u32) -> String {
	format!("{:08x}", value)
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
	fn val(b: u8) -> Option<u8> {
		match b {
			b'A'..=b'Z' => Some(b - b'A'),
			b'a'..=b'z' => Some(b - b'a' + 26),
			b'0'..=b'9' => Some(b - b'0' + 52),
			b'+' => Some(62),
			b'/' => Some(63),
			_ => None,
		}
	}
	let bytes = input.as_bytes();
	let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
	let mut i = 0;
	while i + 4 <= bytes.len() {
		let v0 = val(bytes[i])?;
		let v1 = val(bytes[i + 1])?;
		let v2 = val(bytes[i + 2])?;
		let v3 = val(bytes[i + 3])?;
		out.push((v0 << 2) | (v1 >> 4));
		out.push((v1 << 4) | (v2 >> 2));
		out.push((v2 << 6) | v3);
		i += 4;
	}
	let rem = bytes.len() - i;
	if rem == 2 {
		let v0 = val(bytes[i])?;
		let v1 = val(bytes[i + 1])?;
		out.push((v0 << 2) | (v1 >> 4));
	} else if rem == 3 {
		let v0 = val(bytes[i])?;
		let v1 = val(bytes[i + 1])?;
		let v2 = val(bytes[i + 2])?;
		out.push((v0 << 2) | (v1 >> 4));
		out.push((v1 << 4) | (v2 >> 2));
	}
	Some(out)
}
