mod test_guard;
use redmi_ia::core::ipc::IPC;

fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    *seed
}

#[test]
fn ipc_fuzz_frames_roundtrip() {
    let mut ipc = IPC::new();
    ipc.register_channel("fuzz");
    ipc.configure_channel_limits("fuzz", 512, 256);

    let mut seed = 0x1234_5678_u64;
    for _ in 0..500 {
        let rnd = lcg(&mut seed);
        let len = (rnd as usize % 128).max(1);
        let opcode = (rnd as u16) & 0x0FFF;
        let mut payload = Vec::with_capacity(len);
        for _ in 0..len {
            payload.push((lcg(&mut seed) & 0xFF) as u8);
        }
        let _ = ipc
            .send_packet(1, "fuzz", opcode, &payload, 1, 0)
            .expect("send");
        let frame = ipc.recv_raw("fuzz").expect("recv_raw");
        let msg = ipc.deserialize_message(&frame).expect("decode");
        assert_eq!(msg.opcode, opcode);
        assert_eq!(msg.payload.len(), len);
    }
}
