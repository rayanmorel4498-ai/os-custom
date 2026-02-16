use alloc::vec::Vec;

pub fn encode_u32_le(value: u32, out: &mut Vec<u8>) {
	out.extend_from_slice(&value.to_le_bytes());
}

pub fn decode_u32_le(input: &[u8]) -> Option<(u32, usize)> {
	if input.len() < 4 {
		return None;
	}
	let mut bytes = [0u8; 4];
	bytes.copy_from_slice(&input[..4]);
	Some((u32::from_le_bytes(bytes), 4))
}

pub fn encode_with_len(payload: &[u8], out: &mut Vec<u8>) {
	encode_u32_le(payload.len() as u32, out);
	out.extend_from_slice(payload);
}

pub fn decode_with_len(input: &[u8]) -> Option<(Vec<u8>, usize)> {
	let (len, offset) = decode_u32_le(input)?;
	let len = len as usize;
	if input.len() < offset + len {
		return None;
	}
	let payload = input[offset..offset + len].to_vec();
	Some((payload, offset + len))
}
