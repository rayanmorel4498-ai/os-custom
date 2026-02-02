use core::task::Waker;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use parking_lot::Mutex;

pub struct IoFuture {
    id: u64,
    is_ready: Arc<Mutex<bool>>,
    waker: Arc<Mutex<Option<Waker>>>,
    result: Arc<Mutex<Option<IoResult>>>,
}

#[derive(Clone, Debug)]
pub enum IoResult {
    Success(u32),
    Error(u32),
    Pending,
}

impl IoFuture {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            is_ready: Arc::new(Mutex::new(false)),
            waker: Arc::new(Mutex::new(None)),
            result: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_ready(&self, result: IoResult) {
        *self.is_ready.lock() = true;
        *self.result.lock() = Some(result);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    pub fn take_result(&self) -> Option<IoResult> {
        if *self.is_ready.lock() {
            self.result.lock().take()
        } else {
            None
        }
    }

    pub fn is_ready(&self) -> bool {
        *self.is_ready.lock()
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

pub struct AsyncExecutor {
    pending_futures: Arc<Mutex<VecDeque<Arc<IoFuture>>>>,
    completed_futures: Arc<Mutex<VecDeque<Arc<IoFuture>>>>,
    max_concurrent: usize,
}

impl AsyncExecutor {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            pending_futures: Arc::new(Mutex::new(VecDeque::new())),
            completed_futures: Arc::new(Mutex::new(VecDeque::new())),
            max_concurrent,
        }
    }

    pub fn submit(&self, future: Arc<IoFuture>) -> Result<(), &'static str> {
        let mut pending = self.pending_futures.lock();
        if pending.len() >= self.max_concurrent {
            return Err("Max concurrent I/O operations reached");
        }
        pending.push_back(future);
        Ok(())
    }

    pub fn poll_one(&self) -> Option<Arc<IoFuture>> {
        let mut pending = self.pending_futures.lock();
        if let Some(future) = pending.pop_front() {
            if future.is_ready() {
                drop(pending);
                self.completed_futures.lock().push_back(future.clone());
                Some(future)
            } else {
                pending.push_back(future);
                None
            }
        } else {
            None
        }
    }

    pub fn collect_completed(&self) -> usize {
        self.completed_futures.lock().len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_futures.lock().len()
    }
}

pub struct IoMultiplexer {
    io_events: Arc<Mutex<VecDeque<IoEvent>>>,
    event_id_counter: Arc<Mutex<u64>>,
    active_operations: Arc<Mutex<usize>>,
}

#[derive(Clone, Debug)]
pub struct IoEvent {
    pub id: u64,
    pub device: u32,
    pub op_type: IoOpType,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub enum IoOpType {
    Read,
    Write,
    Seek,
    Flush,
}

impl IoMultiplexer {
    pub fn new() -> Self {
        Self {
            io_events: Arc::new(Mutex::new(VecDeque::new())),
            event_id_counter: Arc::new(Mutex::new(0)),
            active_operations: Arc::new(Mutex::new(0)),
        }
    }

    pub fn register_operation(&self, device: u32, op_type: IoOpType, timestamp: u64) -> u64 {
        let mut counter = self.event_id_counter.lock();
        let id = *counter;
        *counter += 1;

        let event = IoEvent {
            id,
            device,
            op_type,
            timestamp,
        };

        self.io_events.lock().push_back(event);
        *self.active_operations.lock() += 1;
        id
    }

    pub fn next_event(&self) -> Option<IoEvent> {
        self.io_events.lock().pop_front()
    }

    pub fn mark_completed(&self) {
        let mut active = self.active_operations.lock();
        if *active > 0 {
            *active -= 1;
        }
    }

    pub fn active_operations(&self) -> usize {
        *self.active_operations.lock()
    }
}