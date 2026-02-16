use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::prelude::String;
use spin::{Mutex, Once};

pub struct TraceBuffer {
	buffer: VecDeque<String>,
	capacity: usize,
}

impl TraceBuffer {
	pub fn new(capacity: usize) -> Self {
		TraceBuffer {
			buffer: VecDeque::with_capacity(capacity.max(1)),
			capacity: capacity.max(1),
		}
	}

	pub fn push(&mut self, entry: String) {
		if self.buffer.len() >= self.capacity {
			self.buffer.pop_front();
		}
		self.buffer.push_back(entry);
	}

	pub fn drain(&mut self) -> Vec<String> {
		self.buffer.drain(..).collect()
	}

	pub fn snapshot(&self) -> Vec<String> {
		self.buffer.iter().cloned().collect()
	}

	pub fn len(&self) -> usize {
		self.buffer.len()
	}
}

static TRACE: Once<Mutex<TraceBuffer>> = Once::new();

fn trace_buffer() -> &'static Mutex<TraceBuffer> {
	TRACE.call_once(|| Mutex::new(TraceBuffer::new(128)))
}

pub fn trace_event(entry: String) {
	trace_buffer().lock().push(entry);
}

pub fn export_trace() -> Vec<String> {
	trace_buffer().lock().snapshot()
}

pub fn drain_trace() -> Vec<String> {
	trace_buffer().lock().drain()
}

pub fn trace_len() -> usize {
	trace_buffer().lock().len()
}
