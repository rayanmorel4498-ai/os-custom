extern crate alloc;
use alloc::string::{String, ToString};
use alloc::fmt;

#[derive(Debug, Clone)]
pub enum TlsError {
    TokenNotFound { token_id: String },
    TokenExpired { token_id: String },
    TokenRevoked { token_id: String },
    SessionNotFound { session_key: String },
    SessionExpired { session_key: String },
    SignatureVerificationFailed { reason: String },
    SignatureCreationFailed { reason: String },
    InvalidCredentials,
    InsufficientPrivileges { required: u8, actual: u8 },
    InvalidComponentType { component: String },
    EncodingError { reason: String },
    DecodingError { reason: String },
    KeyDerivationFailed { reason: String },
    InternalError { reason: String },
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::TokenNotFound { token_id } => {
                write!(f, "Token not found: {}", token_id)
            }
            TlsError::TokenExpired { token_id } => {
                write!(f, "Token expired: {}", token_id)
            }
            TlsError::TokenRevoked { token_id } => {
                write!(f, "Token revoked: {}", token_id)
            }
            TlsError::SessionNotFound { session_key } => {
                write!(f, "Session not found: {}", session_key)
            }
            TlsError::SessionExpired { session_key } => {
                write!(f, "Session expired: {}", session_key)
            }
            TlsError::SignatureVerificationFailed { reason } => {
                write!(f, "Signature verification failed: {}", reason)
            }
            TlsError::SignatureCreationFailed { reason } => {
                write!(f, "Signature creation failed: {}", reason)
            }
            TlsError::InvalidCredentials => write!(f, "Invalid credentials"),
            TlsError::InsufficientPrivileges { required, actual } => {
                write!(f, "Insufficient privileges: required={}, actual={}", required, actual)
            }
            TlsError::InvalidComponentType { component } => {
                write!(f, "Invalid component type: {}", component)
            }
            TlsError::EncodingError { reason } => {
                write!(f, "Encoding error: {}", reason)
            }
            TlsError::DecodingError { reason } => {
                write!(f, "Decoding error: {}", reason)
            }
            TlsError::KeyDerivationFailed { reason } => {
                write!(f, "Key derivation failed: {}", reason)
            }
            TlsError::InternalError { reason } => {
                write!(f, "Internal error: {}", reason)
            }
        }
    }
}

impl TlsError {
    pub fn token_not_found(token_id: &str) -> Self {
        TlsError::TokenNotFound {
            token_id: token_id.to_string(),
        }
    }

    pub fn session_not_found(session_key: &str) -> Self {
        TlsError::SessionNotFound {
            session_key: session_key.to_string(),
        }
    }

    pub fn insufficient_privileges(required: u8, actual: u8) -> Self {
        TlsError::InsufficientPrivileges { required, actual }
    }

    pub fn code(&self) -> u16 {
        match self {
            TlsError::TokenNotFound { .. } => 1001,
            TlsError::TokenExpired { .. } => 1002,
            TlsError::TokenRevoked { .. } => 1003,
            TlsError::SessionNotFound { .. } => 2001,
            TlsError::SessionExpired { .. } => 2002,
            TlsError::SignatureVerificationFailed { .. } => 3001,
            TlsError::SignatureCreationFailed { .. } => 3002,
            TlsError::InvalidCredentials => 4001,
            TlsError::InsufficientPrivileges { .. } => 4002,
            TlsError::InvalidComponentType { .. } => 5001,
            TlsError::EncodingError { .. } => 6001,
            TlsError::DecodingError { .. } => 6002,
            TlsError::KeyDerivationFailed { .. } => 7001,
            TlsError::InternalError { .. } => 9999,
        }
    }
}

pub type TlsResult<T> = Result<T, TlsError>;
