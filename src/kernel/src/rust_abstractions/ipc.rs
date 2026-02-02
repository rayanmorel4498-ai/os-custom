
use crate::rust_abstractions::concurrency::{Mutex, SpinLock, Semaphore};
use crate::rust_abstractions::threads::ThreadState;

pub const IPC_PAYLOAD_SIZE: usize = 512;

#[derive(Clone)]
pub struct IpcMessage {
    pub sender_id: usize,
    pub receiver_id: usize,
    pub payload: [u8; IPC_PAYLOAD_SIZE],
    pub payload_len: u16,
    pub priority: u8,
}

pub struct IpcQueue {
    messages: [Option<IpcMessage>; 32],
    mutex: Mutex,
    spinlock: SpinLock,
    semaphore: Semaphore,
}

impl IpcQueue {
    pub const fn new() -> Self {
        IpcQueue {
            messages: [None; 32],
            mutex: Mutex::new(),
            spinlock: SpinLock::new(),
            semaphore: Semaphore::new(32),
        }
    }

    pub fn send(&mut self, mut msg: IpcMessage) -> bool {
        if msg.payload_len > IPC_PAYLOAD_SIZE as u16 {
            msg.payload_len = IPC_PAYLOAD_SIZE as u16;
        }

        let critical = msg.priority == 0;

        if critical {
            self.spinlock.lock();
        } else {
            self.mutex.lock();
        }

        let mut added = false;
        for slot in self.messages.iter_mut() {
            if slot.is_none() {
                *slot = Some(msg);
                self.semaphore.acquire();
                added = true;
                break;
            }
        }

        if critical {
            self.spinlock.unlock();
        } else {
            self.mutex.unlock();
        }

        added
    }

    pub fn recv(&mut self) -> Option<IpcMessage> {
        self.mutex.lock();
        let mut msg = None;
        for slot in self.messages.iter_mut() {
            if slot.is_some() {
                msg = slot.take();
                self.semaphore.release();
                break;
            }
        }
        self.mutex.unlock();
        msg
    }

    pub fn available(&self) -> usize {
        self.semaphore.available()
    }
}

pub struct IpcManager {
    pub queues: [IpcQueue; 8],
}

impl IpcManager {
    pub const fn new() -> Self {
        IpcManager {
            queues: [
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
                IpcQueue::new(),
            ],
        }
    }

    pub fn send(&mut self, msg: IpcMessage) -> bool {
        if msg.receiver_id >= self.queues.len() { return false; }
        self.queues[msg.receiver_id].send(msg)
    }

    pub fn recv(&mut self, thread_id: usize) -> Option<IpcMessage> {
        if thread_id >= self.queues.len() { return None; }
        self.queues[thread_id].recv()
    }

    pub fn has_messages(&self, thread_id: usize) -> bool {
        if thread_id >= self.queues.len() { return false; }
        self.queues[thread_id].available() > 0
    }
}

pub struct IpcNotifier {
    pub notified: [SpinLock; 8],
}

impl IpcNotifier {
    pub const fn new() -> Self {
        IpcNotifier {
            notified: [
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
                SpinLock::new(),
            ],
        }
    }

    pub fn notify(&self, thread_id: usize) {
        if thread_id >= 8 { return; }
        self.notified[thread_id].unlock();
    }

    pub fn wait(&self, thread_id: usize) {
        if thread_id >= 8 { return; }
        self.notified[thread_id].lock();
    }
}