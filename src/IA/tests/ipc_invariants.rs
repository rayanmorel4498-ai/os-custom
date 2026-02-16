mod test_guard;
use redmi_ia::core::ipc::{DropPolicy, IPC};

#[test]
fn ipc_ttl_expiry_drops_message() {
    let mut ipc = IPC::new();
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");

    let _ = ipc.send_with_ttl(1, "ch", b"hi", 1, 1).expect("send ok");
    ipc.advance_tick(2);
    ipc.route();

    let msg = ipc.recv(1);
    assert!(msg.is_none());
}

#[test]
fn ipc_anti_replay_rejects_same_message() {
    let mut ipc = IPC::new();
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    ipc.configure_security(Some(b"secret"), true);

    let _ = ipc.send(1, "ch", b"ping", 1).expect("send ok");
    ipc.route();

    let msg = ipc.recv(1).expect("recv ok");
    let replay = ipc.verify_message(&msg);
    assert!(replay.is_err());
}

#[test]
fn ipc_drop_policy_drops_low_priority() {
    let mut ipc = IPC::new();
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    ipc.configure_backpressure(8, 1, 8, DropPolicy::DropLowPriority);

    let _ = ipc.send(1, "ch", b"low", 1).expect("send low");
    let _ = ipc.send(1, "ch", b"high", 9).expect("send high");

    ipc.route();
    let first = ipc.recv(1).expect("recv ok");
    assert_eq!(first.payload, b"high".to_vec());
    assert!(ipc.recv(1).is_none());
}
