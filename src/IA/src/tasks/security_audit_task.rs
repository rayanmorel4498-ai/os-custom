use crate::prelude::String;

#[derive(Debug, Clone)]
pub enum SecurityIssue {
    UnauthorizedAccess,
    InvalidChecksum,
    MemorySafety,
    Other(String),
}

pub struct SecurityAuditor {
    issues: alloc::vec::Vec<SecurityIssue>,
    authorized_users: alloc::vec::Vec<u32>,
}

impl SecurityAuditor {
    pub fn new() -> Self {
        SecurityAuditor {
            issues: alloc::vec::Vec::new(),
            authorized_users: alloc::vec::Vec::new(),
        }
    }

    pub fn authorize_user(&mut self, user_id: u32) {
        self.authorized_users.push(user_id);
    }

    pub fn audit_access(&mut self, user_id: u32) -> bool {
        if self.authorized_users.contains(&user_id) {
            true
        } else {
            self.issues.push(SecurityIssue::UnauthorizedAccess);
            false
        }
    }

    pub fn report_issue(&mut self, issue: SecurityIssue) {
        self.issues.push(issue);
    }

    pub fn get_issues(&self) -> &[SecurityIssue] {
        &self.issues
    }

    pub fn is_secure(&self) -> bool {
        self.issues.is_empty()
    }
}
