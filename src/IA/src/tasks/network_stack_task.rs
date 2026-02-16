use crate::prelude::Vec;

#[derive(Clone)]
pub struct Packet {
    src: u32,
    dst: u32,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(src: u32, dst: u32, payload: Vec<u8>) -> Self {
        Packet { src, dst, payload }
    }

    pub fn src(&self) -> u32 {
        self.src
    }

    pub fn dst(&self) -> u32 {
        self.dst
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub struct NetworkStack {
    rx_queue: Vec<Packet>,
    tx_queue: Vec<Packet>,
}

impl NetworkStack {
    pub fn new() -> Self {
        NetworkStack {
            rx_queue: Vec::new(),
            tx_queue: Vec::new(),
        }
    }

    pub fn send(&mut self, packet: Packet) {
        self.tx_queue.push(packet);
    }

    pub fn recv(&mut self) -> Option<Packet> {
        if self.rx_queue.is_empty() {
            None
        } else {
            Some(self.rx_queue.remove(0))
        }
    }

    pub fn rx_len(&self) -> usize {
        self.rx_queue.len()
    }

    pub fn tx_len(&self) -> usize {
        self.tx_queue.len()
    }
}
