mod test_guard;
use redmi_ia::core::ipc::{IPCMessage, IPC, IPC_PROTOCOL_VERSION};

#[test]
fn ipc_rejects_bad_signature() {
    let mut ipc = IPC::new();
    ipc.configure_security(Some(b"secret"), true);
    let msg = IPCMessage {
        id: 1,
        channel: "ch".into(),
        payload: b"payload".to_vec(),
        api_version: 1,
        priority: 1,
        sender: 1,
        nonce: 1,
        created_tick: 0,
        ttl_ticks: 10,
        retries: 0,
        signature: Some([0u8; 32]),
        version: IPC_PROTOCOL_VERSION,
        opcode: 1,
        crc: 0,
    };
    let data = ipc.serialize_message(&msg).expect("serialize");
    let res = ipc.deserialize_message(&data);
    assert!(res.is_err());
}

#[test]
fn ipc_untrusted_timestamp_allows_deserialize() {
    let mut ipc = IPC::new();
    ipc.configure_timestamp_policy(redmi_ia::core::ipc::TimestampPolicy::Untrusted);
    let msg = IPCMessage {
        id: 2,
        channel: "ch".into(),
        payload: b"payload".to_vec(),
        api_version: 1,
        priority: 1,
        sender: 1,
        nonce: 2,
        created_tick: 999_999,
        ttl_ticks: 10,
        retries: 0,
        signature: None,
        version: IPC_PROTOCOL_VERSION,
        opcode: 2,
        crc: 0,
    };
    let data = ipc.serialize_message(&msg).expect("serialize");
    let res = ipc.deserialize_message(&data);
    assert!(res.is_ok());
}
