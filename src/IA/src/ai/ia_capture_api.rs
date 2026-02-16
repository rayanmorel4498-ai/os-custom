// API d'accès IA aux flux du capture_module via IPC strict
use crate::ai::ia_capture_client::IaCaptureClient;

pub fn ia_capture_audio(buffer: &mut [u8]) -> usize {
    let client = IaCaptureClient::new();
    match client.capture_audio(buffer.len()) {
        Ok(payload) => {
            let copy_len = core::cmp::min(buffer.len(), payload.len());
            buffer[..copy_len].copy_from_slice(&payload[..copy_len]);
            copy_len
        }
        Err(_) => 0,
    }
}

pub fn ia_capture_video(buffer: &mut [u8]) -> usize {
    let client = IaCaptureClient::new();
    match client.capture_video(buffer.len()) {
        Ok(payload) => {
            let copy_len = core::cmp::min(buffer.len(), payload.len());
            buffer[..copy_len].copy_from_slice(&payload[..copy_len]);
            copy_len
        }
        Err(_) => 0,
    }
}
