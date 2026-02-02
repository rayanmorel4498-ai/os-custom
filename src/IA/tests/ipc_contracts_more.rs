use redmi_ia::core::ipc::{IPC, TimestampPolicy};

#[test]
fn ipc_contract_min_payload_enforced() {
    let mut ipc = IPC::new();
    ipc.configure_api_contract(1, 4, true);
    let res = ipc.send(1, "ch", b"x", 1);
    assert!(res.is_err());
}

#[test]
fn ipc_required_timestamp_skew_rejects() {
    let mut ipc = IPC::new();
    ipc.configure_security(Some(b"test-secret"), true);
    ipc.configure_timestamp_policy(TimestampPolicy::Required);
    ipc.configure_time_skew(1);
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    let _ = ipc.send(1, "ch", b"x", 1).expect("send");
    ipc.advance_tick(10);
    ipc.route();
    let msg = ipc.recv(1);
    assert!(msg.is_none());
}
