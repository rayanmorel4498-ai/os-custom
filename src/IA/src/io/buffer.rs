use alloc::vec::Vec;

pub struct ByteBuffer {
	buf: Vec<u8>,
	read_pos: usize,
	max_size: Option<usize>,
}

impl ByteBuffer {
	pub fn new() -> Self {
		ByteBuffer {
			buf: Vec::new(),
			read_pos: 0,
			max_size: None,
		}
	}

	pub fn with_capacity(capacity: usize) -> Self {
		ByteBuffer {
			buf: Vec::with_capacity(capacity),
			read_pos: 0,
			max_size: None,
		}
	}

	pub fn set_max_size(&mut self, max_size: Option<usize>) {
		self.max_size = max_size;
		if let Some(limit) = self.max_size {
			if self.buf.len() > limit {
				self.buf.truncate(limit);
				self.read_pos = self.read_pos.min(self.buf.len());
			}
		}
	}

	pub fn len(&self) -> usize {
		self.buf.len().saturating_sub(self.read_pos)
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	pub fn clear(&mut self) {
		self.buf.clear();
		self.read_pos = 0;
	}

	pub fn shrink_to_fit(&mut self) {
		if self.read_pos > 0 {
			self.buf.drain(..self.read_pos);
			self.read_pos = 0;
		}
		self.buf.shrink_to_fit();
	}

	pub fn push(&mut self, byte: u8) {
		if let Some(limit) = self.max_size {
			if self.buf.len() >= limit {
				return;
			}
		}
		self.buf.push(byte);
	}

	pub fn extend_from_slice(&mut self, data: &[u8]) {
		if let Some(limit) = self.max_size {
			if self.buf.len() >= limit {
				return;
			}
			let remaining = limit.saturating_sub(self.buf.len());
			self.buf.extend_from_slice(&data[..data.len().min(remaining)]);
			return;
		}
		self.buf.extend_from_slice(data);
	}

	pub fn pop(&mut self) -> Option<u8> {
		if self.read_pos >= self.buf.len() {
			return None;
		}
		let byte = self.buf[self.read_pos];
		self.read_pos = self.read_pos.saturating_add(1);
		Some(byte)
	}

	pub fn read(&mut self, out: &mut [u8]) -> usize {
		let available = self.len();
		let to_read = out.len().min(available);
		for i in 0..to_read {
			if let Some(b) = self.pop() {
				out[i] = b;
			}
		}
		to_read
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.buf[self.read_pos..]
	}
}

impl Default for ByteBuffer {
	fn default() -> Self {
		Self::new()
	}
}
