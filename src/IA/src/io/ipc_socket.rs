use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

type SendFn = fn(path: &str, payload: &[u8]) -> bool;
type RecvFn = fn(path: &str) -> Option<Vec<u8>>;

#[derive(Clone, Copy)]
pub struct IpcBackend {
	send_fn: SendFn,
	recv_fn: RecvFn,
}

static BACKEND: Mutex<Option<IpcBackend>> = Mutex::new(None);

pub fn set_backend(send_fn: SendFn, recv_fn: RecvFn) {
	*BACKEND.lock() = Some(IpcBackend { send_fn, recv_fn });
}

pub fn clear_backend() {
	*BACKEND.lock() = None;
}

pub fn send(path: &str, payload: Vec<u8>) -> Result<(), String> {
	let backend = BACKEND.lock().clone().ok_or_else(|| String::from("ipc_socket: no backend"))?;
	if (backend.send_fn)(path, &payload) {
		Ok(())
	} else {
		Err(String::from("ipc_socket: send failed"))
	}
}

pub fn recv(path: &str) -> Option<Vec<u8>> {
	let backend = BACKEND.lock().clone()?;
	(backend.recv_fn)(path)
}
