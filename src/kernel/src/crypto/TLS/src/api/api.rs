
extern crate alloc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use serde_json::{self, json, Value};

use crate::api::token::TokenManager;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiRequest {
    pub command: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub valid_for_secs: u64,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub count: usize,
}

#[derive(Debug, Serialize, Default)]
pub struct ApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[allow(dead_code)]
pub fn process_request_bytes(input: &str, tm: &Arc<TokenManager>) -> Result<String> {
    match serde_json::from_str::<ApiRequest>(input) {
        Ok(req) => {
            let resp = process_request(&req, tm);
            let s = serde_json::to_string(&resp)?;
            Ok(s)
        }
        Err(e) => {
            let resp = ApiResponse { success: false, message: Some(format!("JSON parse error: {}", e)), ..Default::default() };
            Ok(serde_json::to_string(&resp)?)
        }
    }
}

#[allow(dead_code)]
pub fn process_request(req: &ApiRequest, tm: &Arc<TokenManager>) -> ApiResponse {
    match req.command.as_str() {
        "generate" => {
            if req.context.is_empty() {
                return ApiResponse {
                    success: false,
                    message: Some("context required".to_string()),
                    ..Default::default()
                };
            }
            let valid_for = if req.valid_for_secs > 0 {
                req.valid_for_secs
            } else {
                60
            };
            match tm.generate(&req.context, valid_for) {
                Some(token) => ApiResponse {
                    success: true,
                    token: Some(token),
                    ..Default::default()
                },
                None => ApiResponse {
                    success: false,
                    message: Some("token generation failed".to_string()),
                    ..Default::default()
                },
            }
        }

        "validate" => {
            if req.context.is_empty() {
                return ApiResponse {
                    success: false,
                    message: Some("context is required for validate".to_string()),
                    ..Default::default()
                };
            }

            let valid = tm.validate_with_context(&req.token, &req.context);
            ApiResponse {
                success: true,
                valid: Some(valid),
                ..Default::default()
            }
        }

        "generate_honeypot" => {
            let count = if req.count > 0 { req.count } else { 1 };
            let tokens = tm.generate_acces(count);
            ApiResponse {
                success: true,
                tokens: Some(tokens),
                ..Default::default()
            }
        }

        "list_tokens" => {
            let list = tm.list_tokens();
            let tokens: Vec<Value> = list.into_iter().map(|(ctx, exp)| {
                json!({"context": ctx, "expiry": exp})
            }).collect();
            ApiResponse {
                success: true,
                tokens: Some(tokens.into_iter().map(|v| v.to_string()).collect()),
                ..Default::default()
            }
        }

        "purge_expired" => {
            let purged = tm.purge_expired();
            ApiResponse {
                success: true,
                message: Some(format!("purged {} entries", purged)),
                ..Default::default()
            }
        }

        _ => ApiResponse {
            success: false,
            message: Some(format!("unknown command: {}", req.command)),
            ..Default::default()
        },
    }
}

