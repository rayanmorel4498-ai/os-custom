use alloc::vec::Vec;

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone)]
pub struct ParamMessage {
    pub version: u8,
    pub payload: Vec<f64>,
}

impl ParamMessage {
    pub fn new(payload: Vec<f64>) -> Self {
        ParamMessage {
            version: PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        let len = self.payload.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        for v in self.payload.iter() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    pub fn decode(input: &[u8]) -> Option<Self> {
        if input.len() < 5 {
            return None;
        }
        let version = input[0];
        if version != PROTOCOL_VERSION {
            return None;
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&input[1..5]);
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut offset = 5;
        let mut payload = Vec::new();
        for _ in 0..len {
            if input.len() < offset + 8 {
                return None;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&input[offset..offset + 8]);
            payload.push(f64::from_le_bytes(buf));
            offset += 8;
        }
        Some(ParamMessage { version, payload })
    }
}

pub fn start_parameter_server(_addr: &str, _expected_clients: usize) {
    // No-op in no_std stub. Real server lives in the ml_full feature.
}

pub fn client_send_weights(_server_addr: &str, weights: &[f64]) -> Option<Vec<f64>> {
    // Stable protocol encode/decode path for integration tests.
    let msg = ParamMessage::new(weights.to_vec());
    let encoded = msg.encode();
    ParamMessage::decode(&encoded).map(|m| m.payload)
}
