use crate::prelude::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ErrTimeout,
    ErrInvalidInput,
    ErrUnauthorized,
    ErrBusy,
    ErrNotFound,
    ErrInternal,
    ErrUnavailable,
    ErrQuotaExceeded,
    ErrProtocol,
    ErrIntegrity,
    ErrCircuitOpen,
    ErrUnknown,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::ErrTimeout => "ERR_TIMEOUT",
            ErrorCode::ErrInvalidInput => "ERR_INVALID_INPUT",
            ErrorCode::ErrUnauthorized => "ERR_UNAUTHORIZED",
            ErrorCode::ErrBusy => "ERR_BUSY",
            ErrorCode::ErrNotFound => "ERR_NOT_FOUND",
            ErrorCode::ErrInternal => "ERR_INTERNAL",
            ErrorCode::ErrUnavailable => "ERR_UNAVAILABLE",
            ErrorCode::ErrQuotaExceeded => "ERR_QUOTA_EXCEEDED",
            ErrorCode::ErrProtocol => "ERR_PROTOCOL",
            ErrorCode::ErrIntegrity => "ERR_INTEGRITY",
            ErrorCode::ErrCircuitOpen => "ERR_CIRCUIT_OPEN",
            ErrorCode::ErrUnknown => "ERR_UNKNOWN",
        }
    }

    pub fn is_transient(&self) -> bool {
        matches!(self, ErrorCode::ErrTimeout | ErrorCode::ErrBusy)
    }
}

pub fn is_transient_str(message: &str) -> bool {
    message.starts_with(ErrorCode::ErrTimeout.as_str())
        || message.starts_with(ErrorCode::ErrBusy.as_str())
}

#[derive(Debug)]
pub enum Error {
    Code(ErrorCode, String),
    Custom(String),
    CommunicationError(String),
}

impl Error {
    pub fn code(code: ErrorCode, context: &str) -> Self {
        Error::Code(code, context.into())
    }

    pub fn code_str(code: ErrorCode, context: &str) -> String {
        alloc::format!("{}:{}", code.as_str(), context)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
pub type EngineError = Error;
