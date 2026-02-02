use redmi_ia::core::ipc::{DropPolicy, IPC};

#[test]
fn ipc_retry_pending_returns_ids() {
    let mut ipc = IPC::new();
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    ipc.configure_retry(3, true, 1, 8, 10);

    let id = ipc.send(1, "ch", b"x", 1).expect("send ok");
    ipc.advance_tick(2);
    let retried = ipc.retry_pending();
    assert!(retried.contains(&id));
}

#[test]
fn ipc_backpressure_drop_oldest() {
    let mut ipc = IPC::new();
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    ipc.configure_backpressure(2, 2, 2, DropPolicy::DropOldest);

    let _ = ipc.send(1, "ch", b"a", 1).expect("a");
    let _ = ipc.send(1, "ch", b"b", 1).expect("b");
    let _ = ipc.send(1, "ch", b"c", 1).expect("c");

    ipc.route();
    let first = ipc.recv(1).unwrap();
    assert_ne!(first.payload, b"a".to_vec());
}
