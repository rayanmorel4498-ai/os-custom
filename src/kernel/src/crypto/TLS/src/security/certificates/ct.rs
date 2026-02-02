extern crate alloc;

#[cfg_attr(not(feature = "real_tls"), allow(dead_code))]

use subtle::ConstantTimeEq;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	a.ct_eq(b).unwrap_u8() == 1
}

pub fn constant_time_compare_fingerprints(fp1: &str, fp2: &str) -> bool {
	if fp1.len() != fp2.len() {
		return false;
	}
	let b1 = fp1.as_bytes();
	let b2 = fp2.as_bytes();
	b1.ct_eq(b2).unwrap_u8() == 1
}

pub fn constant_time_hash_compare(hash1: &[u8], hash2: &[u8]) -> bool {
	if hash1.len() != hash2.len() {
		return false;
	}
	hash1.ct_eq(hash2).unwrap_u8() == 1
}

pub fn constant_time_key_compare(key1: &[u8], key2: &[u8]) -> bool {
	if key1.len() != key2.len() {
		return false;
	}
	key1.ct_eq(key2).unwrap_u8() == 1
}

pub fn safe_timing_resistant_compare(left: &[u8], right: &[u8]) -> Result<bool, &'static str> {
	if left.len() != right.len() {
		return Err("length mismatch");
	}
	
	let result = left.ct_eq(right).unwrap_u8() == 1;
	Ok(result)
}
pub fn hex_encode(bytes: &[u8]) -> alloc::string::String {
	const HEX_CHARS: &[u8] = b"0123456789abcdef";
	let mut result = alloc::string::String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		result.push(HEX_CHARS[(byte >> 4) as usize] as char);
		result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
	}
	result
}