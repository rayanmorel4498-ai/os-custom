
extern crate alloc;
use alloc::string::String;

use crate::api::component_token::{ComponentTokenManager, ComponentType, ComponentSignature};
use crate::services::session_manager::SessionManager;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use alloc::sync::Arc;

#[cfg(test)]
use alloc::string::ToString;

#[derive(Serialize, Deserialize)]
pub struct IssueTokenRequest {
    pub component: String,
    pub instance_id: u32,
    pub valid_for_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub struct IssueTokenResponse {
    pub token_id: String,
    pub token_value: String,
    pub public_key: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SignActionRequest {
    pub token_id: String,
    pub message: String,
    pub nonce: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignActionResponse {
    pub token_id: String,
    pub message: String,
    pub signature: String,
    pub signed_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct VerifySignatureRequest {
    pub token_id: String,
    pub message: String,
    pub signature: String,
    pub signed_at: u64,
    pub nonce: String,
}

#[derive(Serialize, Deserialize)]
pub struct ValidateTokenRequest {
    pub token_id: String,
    pub token_value: String,
}

#[derive(Serialize, Deserialize)]
pub struct OpenSessionRequest {
    pub component: String,
    pub instance_id: u32,
}

#[derive(Serialize, Deserialize)]
pub struct OpenSessionResponse {
    pub token_id: String,
    pub token_value: String,
    pub public_key: String,
    pub session_opened_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub component: String,
    pub instance_id: u32,
}

#[derive(Serialize, Deserialize)]
pub struct RotateTokenRequest {
    pub component: String,
    pub instance_id: u32,
}


pub struct ComponentAPIHandler {
    token_mgr: Arc<ComponentTokenManager>,
    session_mgr: Arc<SessionManager>,
}

impl ComponentAPIHandler {
    pub fn new(
        master_key: &str,
        session_timeout: u64,
        token_lifetime: u64,
    ) -> Self {
        let token_mgr = Arc::new(ComponentTokenManager::new(master_key));
        let session_mgr = Arc::new(SessionManager::with_token_mgr(
            Arc::clone(&token_mgr),
            session_timeout,
            token_lifetime,
        ));

        Self {
            token_mgr,
            session_mgr,
        }
    }


    pub fn issue_token(&self, req: IssueTokenRequest) -> Result<IssueTokenResponse> {
        let component = self.parse_component(&req.component)?;
        let token = self
            .session_mgr
            .issue_token(component, req.instance_id, req.valid_for_secs)?;

        Ok(IssueTokenResponse {
            token_id: token.token_id,
            token_value: token.token_value,
            public_key: token.public_key,
            created_at: token.created_at,
            expires_at: token.expires_at,
        })
    }


    pub fn validate_token(&self, req: ValidateTokenRequest) -> Result<bool> {
        self.token_mgr.validate_token(&req.token_id, &req.token_value)
    }


    pub fn sign_action(&self, req: SignActionRequest) -> Result<SignActionResponse> {
        let sig = self
            .token_mgr
            .sign_action(&req.token_id, &req.message, &req.nonce)?;

        Ok(SignActionResponse {
            token_id: sig.token_id,
            message: sig.message,
            signature: sig.signature,
            signed_at: sig.signed_at,
        })
    }


    pub fn verify_signature(&self, req: VerifySignatureRequest) -> Result<bool> {
        let sig = ComponentSignature {
            token_id: req.token_id,
            message: req.message,
            signature: req.signature,
            signed_at: req.signed_at,
            nonce: req.nonce,
        };

        self.token_mgr.verify_signature(&sig)
    }


    pub fn open_session(&self, req: OpenSessionRequest) -> Result<OpenSessionResponse> {
        let component = self.parse_component(&req.component)?;

        let session = self
            .session_mgr
            .open_session(component, req.instance_id, None)?;

        Ok(OpenSessionResponse {
            token_id: session.token.token_id,
            token_value: session.token.token_value,
            public_key: session.token.public_key,
            session_opened_at: session.token.created_at,
        })
    }


    pub fn close_session(
        &self,
        component: String,
        instance_id: u32,
    ) -> Result<()> {
        let comp = self.parse_component(&component)?;
        self.session_mgr.close_session(comp, instance_id)
    }


    pub fn heartbeat(&self, req: HeartbeatRequest) -> Result<()> {
        let component = self.parse_component(&req.component)?;
        self.session_mgr.heartbeat(component, req.instance_id)
    }


    pub fn rotate_token(&self, req: RotateTokenRequest) -> Result<IssueTokenResponse> {
        let component = self.parse_component(&req.component)?;

        let token = self
            .session_mgr
            .rotate_token(component, req.instance_id)?;

        Ok(IssueTokenResponse {
            token_id: token.token_id,
            token_value: token.token_value,
            public_key: token.public_key,
            created_at: token.created_at,
            expires_at: token.expires_at,
        })
    }


    pub fn session_stats(
        &self,
        component: String,
        instance_id: u32,
    ) -> Result<serde_json::Value> {
        let comp = self.parse_component(&component)?;
        let stats = self.session_mgr.session_stats(comp, instance_id)?;
        Ok(serde_json::to_value(stats)?)
    }


    pub fn list_sessions(&self) -> Result<serde_json::Value> {
        let sessions = self.session_mgr.list_sessions();
        Ok(serde_json::to_value(sessions)?)
    }


    fn parse_component(&self, s: &str) -> Result<ComponentType> {
        match s.to_lowercase().as_str() {
            "kernel" => Ok(ComponentType::Kernel),
            "cpu" => Ok(ComponentType::CPU),
            "gpu" => Ok(ComponentType::GPU),
            "ram" => Ok(ComponentType::RAM),
            "thermal" => Ok(ComponentType::Thermal),
            "os" => Ok(ComponentType::OS),
            "ia" => Ok(ComponentType::IA),
            "identity" => Ok(ComponentType::Identity),
            "permissions" => Ok(ComponentType::Permissions),
            "network" => Ok(ComponentType::Network),
            "firewall" => Ok(ComponentType::Firewall),
            "messaging" => Ok(ComponentType::Messaging),
            "calling" => Ok(ComponentType::Calling),
            "location" => Ok(ComponentType::Location),
            "anti_theft" | "anti-theft" => Ok(ComponentType::AntiTheft),
            "front_camera" | "front-camera" => Ok(ComponentType::FrontCamera),
            "rear_camera" | "rear-camera" => Ok(ComponentType::RearCamera),
            "gps" => Ok(ComponentType::GPS),
            "nfc" => Ok(ComponentType::NFC),
            "modem" => Ok(ComponentType::Modem),
            "display" => Ok(ComponentType::Display),
            "audio" => Ok(ComponentType::Audio),
            "haptics" => Ok(ComponentType::Haptics),
            "biometric" => Ok(ComponentType::Biometric),
            "power" => Ok(ComponentType::Power),
            _ => Err(anyhow::anyhow!("Composant inconnu: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_token_api() {
        let api = ComponentAPIHandler::new("test_key", 300, 600);
        let req = IssueTokenRequest {
            component: "cpu".to_string(),
            instance_id: 0,
            valid_for_secs: 3600,
        };

        let res = api.issue_token(req).unwrap();
        assert!(!res.token_id.is_empty());
        assert!(!res.token_value.is_empty());
    }

    #[test]
    fn test_open_session_api() {
        let api = ComponentAPIHandler::new("test_key", 300, 600);
        let req = OpenSessionRequest {
            component: "gpu".to_string(),
            instance_id: 0,
        };

        let res = api.open_session(req).unwrap();
        assert!(!res.token_id.is_empty());
    }
}
