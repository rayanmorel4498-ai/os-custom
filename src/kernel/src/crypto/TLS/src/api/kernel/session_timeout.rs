
use super::spinlock::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::collections::VecDeque;

pub type TimeoutCallback = fn(session_id: u64);

pub struct TimeoutSession {
    pub session_id: u64,
    pub created_at: u64,
    pub timeout_secs: u64,
    pub last_activity: u64,
}

impl TimeoutSession {
    pub fn new(session_id: u64, timeout_secs: u64) -> Self {
        let now = super::callbacks::kernel_get_time_ms() / 1000;
        TimeoutSession {
            session_id,
            created_at: now,
            timeout_secs,
            last_activity: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = super::callbacks::kernel_get_time_ms() / 1000;
        now.saturating_sub(self.last_activity) > self.timeout_secs
    }

    pub fn touch(&mut self) {
        self.last_activity = super::callbacks::kernel_get_time_ms() / 1000;
    }
}

static SESSION_TIMEOUTS: SpinLock<VecDeque<TimeoutSession>> = SpinLock::new(VecDeque::new());
static TIMEOUT_CALLBACK: AtomicUsize = AtomicUsize::new(0);

pub fn init_timeout_callback(callback: TimeoutCallback) {
    TIMEOUT_CALLBACK.store(callback as usize, Ordering::Release);
}

pub fn register_session(session: TimeoutSession) -> Result<(), &'static str> {
    let mut sessions = SESSION_TIMEOUTS.lock();
    if sessions.len() >= 10000 {
        return Err("session_registry_full");
    }
    sessions.push_back(session);
    Ok(())
}

pub fn touch_session(session_id: u64) -> Result<(), &'static str> {
    let mut sessions = SESSION_TIMEOUTS.lock();
    for session in sessions.iter_mut() {
        if session.session_id == session_id {
            session.touch();
            return Ok(());
        }
    }
    Err("session_not_found")
}

pub fn unregister_session(session_id: u64) -> Result<(), &'static str> {
    let mut sessions = SESSION_TIMEOUTS.lock();
    if let Some(pos) = sessions.iter().position(|s| s.session_id == session_id) {
        sessions.remove(pos);
        Ok(())
    } else {
        Err("session_not_found")
    }
}

pub fn purge_expired_sessions() -> u32 {
    let callback_addr = TIMEOUT_CALLBACK.load(Ordering::Acquire);
    let mut purged = 0;
    
    let mut sessions = SESSION_TIMEOUTS.lock();
    let mut to_remove = VecDeque::new();
    
    for (idx, session) in sessions.iter().enumerate() {
        if session.is_expired() {
            to_remove.push_back(idx);
            purged += 1;
        }
    }
    
    while let Some(idx) = to_remove.pop_back() {
        if let Some(session) = sessions.remove(idx) {
            if callback_addr != 0 {
                let callback: TimeoutCallback = unsafe { core::mem::transmute(callback_addr) };
                callback(session.session_id);
            }
        }
    }
    
    purged
}

pub fn session_count() -> usize {
    let sessions = SESSION_TIMEOUTS.lock();
    sessions.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_detection() {
        let mut session = TimeoutSession::new(1, 10);
        assert!(!session.is_expired());
        session.last_activity = 0;
    }

    #[test]
    fn test_session_touch() {
        let mut session = TimeoutSession::new(1, 10);
        let initial = session.last_activity;
        super::super::callbacks::kernel_sleep_ms(100);
        session.touch();
        assert!(session.last_activity >= initial);
    }
}
