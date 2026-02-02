use crate::prelude::{String, format};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrivacyModeState {
    Normal,
    Boost,
}

pub struct PrivacyMode {
    state: PrivacyModeState,
}

impl PrivacyMode {
    pub fn new() -> Self {
        PrivacyMode { state: PrivacyModeState::Normal }
    }

    pub fn enable_boost(&mut self) {
        self.state = PrivacyModeState::Boost;
    }

    pub fn disable_boost(&mut self) {
        self.state = PrivacyModeState::Normal;
    }

    pub fn is_enabled(&self) -> bool {
        self.state == PrivacyModeState::Boost
    }

    pub fn export(&self) -> String {
        let state = match self.state {
            PrivacyModeState::Normal => "normal",
            PrivacyModeState::Boost => "boost",
        };
        format!("privacy_mode={}", state)
    }
}

impl Default for PrivacyMode {
    fn default() -> Self {
        Self::new()
    }
}
