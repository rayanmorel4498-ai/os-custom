mod test_guard;
use redmi_ia::core::ipc::{IPCMessage, TimestampPolicy, IPC, IPC_PROTOCOL_VERSION};

#[test]
fn ipc_contract_version_mismatch() {
    let mut ipc = IPC::new();
    ipc.configure_api_versions(2, 2);
    ipc.configure_api_contract(2, 1, true);
    let msg = IPCMessage {
        id: 1,
        channel: "ch".into(),
        payload: b"x".to_vec(),
        api_version: 1,
        priority: 1,
        sender: 1,
        nonce: 1,
        created_tick: 0,
        ttl_ticks: 10,
        retries: 0,
        signature: None,
        version: IPC_PROTOCOL_VERSION,
        opcode: 1,
        crc: 0,
    };
    let data = ipc.serialize_message(&msg).expect("serialize");
    let res = ipc.deserialize_message(&data);
    assert!(res.is_err());
}

#[test]
fn ipc_channel_quota_enforced() {
    let mut ipc = IPC::new();
    ipc.register_channel("q");
    ipc.configure_channel_quota(1, 1);
    let _ = ipc.send(1, "q", b"a", 1).expect("first ok");
    let second = ipc.send(1, "q", b"b", 1);
    assert!(second.is_err());
}

#[test]
fn ipc_untrusted_timestamp_policy_allows_receive() {
    let mut ipc = IPC::new();
    ipc.configure_timestamp_policy(TimestampPolicy::Untrusted);
    ipc.register_channel("ch");
    ipc.subscribe(1, "ch");
    let _ = ipc.send(1, "ch", b"z", 1).expect("send ok");
    ipc.route();
    let msg = ipc.recv(1);
    assert!(msg.is_some());
}
