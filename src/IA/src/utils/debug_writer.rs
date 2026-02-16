pub struct DebugWriter {}

impl DebugWriter {
    pub fn new() -> Self {
        DebugWriter {}
    }

    pub fn info(msg: &str) {
        crate::utils::logger::info("debug", crate::utils::error::ErrorCode::ErrUnknown, msg);
    }

    pub fn warn(msg: &str) {
        crate::utils::logger::warn("debug", crate::utils::error::ErrorCode::ErrUnknown, msg);
    }
}


