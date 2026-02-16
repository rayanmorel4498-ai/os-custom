use alloc::vec::Vec;

pub const IPC_VERSION: u16 = 1;
pub const IPC_MAX_PAYLOAD_BYTES: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpcSchemaVersion {
	V1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpcTargetClass {
	Core,
	Security,
	Modules,
	Storage,
	Device,
	Ui,
}

#[derive(Clone, Copy)]
pub struct IpcChannelQuota {
	pub max_messages: u32,
	pub window_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IpcCapability {
	pub allow_core: bool,
	pub allow_security: bool,
	pub allow_modules: bool,
	pub allow_storage: bool,
	pub allow_device: bool,
	pub allow_ui: bool,
}

#[derive(Clone)]
pub struct IpcMessage {
	pub version: u16,
	pub opcode: u16,
	pub nonce: u64,
	pub checksum: Option<u32>,
	pub auth_tag: Option<u64>,
	pub payload: Vec<u8>,
}

impl IpcMessage {
	pub fn with_checksum(mut self) -> Self {
		self.checksum = Some(Self::compute_checksum(&self.payload));
		self
	}

	pub fn with_auth(mut self, key: u64) -> Self {
		self.auth_tag = Some(Self::compute_auth_tag(&self.payload, self.nonce, key));
		self
	}

	pub fn validate(&self) -> Result<(), &'static str> {
		if self.version != IPC_VERSION {
			return Err("ipc: version mismatch");
		}
		if self.payload.len() > IPC_MAX_PAYLOAD_BYTES {
			return Err("ipc: payload too large");
		}
		if let Some(expected) = self.checksum {
			let actual = Self::compute_checksum(&self.payload);
			if expected != actual {
				return Err("ipc: checksum mismatch");
			}
		}
		Ok(())
	}

	pub fn validate_auth(&self, key: u64) -> Result<(), &'static str> {
		let tag = self.auth_tag.ok_or("ipc: missing auth_tag")?;
		let expected = Self::compute_auth_tag(&self.payload, self.nonce, key);
		if tag != expected {
			return Err("ipc: auth tag mismatch");
		}
		Ok(())
	}

	fn compute_checksum(payload: &[u8]) -> u32 {
		payload.iter().fold(0u32, |acc, b| acc.wrapping_add(*b as u32))
	}

	fn compute_auth_tag(payload: &[u8], nonce: u64, key: u64) -> u64 {
		let checksum = Self::compute_checksum(payload) as u64;
		checksum ^ nonce ^ key
	}
}
