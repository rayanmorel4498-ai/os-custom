use crate::prelude::Vec;

pub struct ProtocolValidator {
    version: u8,
    checksum_enabled: bool,
}

impl ProtocolValidator {
    pub fn new(version: u8) -> Self {
        ProtocolValidator {
            version,
            checksum_enabled: true,
        }
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        if data[0] != self.version {
            return false;
        }

        if self.checksum_enabled && data.len() >= 2 {
            let stored_checksum = data[data.len() - 1];
            let computed = self.compute_checksum(&data[..data.len() - 1]);
            computed == stored_checksum
        } else {
            true
        }
    }

    fn compute_checksum(&self, data: &[u8]) -> u8 {
        data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
    }

    pub fn add_checksum(&self, data: &mut Vec<u8>) {
        let checksum = self.compute_checksum(data);
        data.push(checksum);
    }
}
