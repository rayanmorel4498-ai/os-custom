mod test_guard;
use redmi_ia::handlers::ipc::{
    route_with_quota, set_channel_capabilities, set_channel_quota, set_channel_require_auth,
    IpcCapability, IpcMessage, IpcTargetClass,
};
use redmi_ia::init::set_locked;
use redmi_ia::security::tls::bundle::{store_bundle, TlsBundle};

#[test]
fn ipc_auth_nonce_checksum_and_quota() {
    let channel = "secure";
    set_locked(false);
    store_bundle(TlsBundle {
        ticket: "t".into(),
        routes: Vec::new(),
        expires_at_ms: 1_000_000,
        generation: 1,
    });
    set_channel_quota(channel, 2, 1000);
    set_channel_require_auth(channel, true);
    set_channel_capabilities(
        channel,
        IpcCapability {
            allow_core: true,
            allow_security: false,
            allow_modules: false,
            allow_storage: false,
            allow_device: false,
            allow_ui: false,
        },
    );

    let key = 0xA5A5_1234_u64;
    let msg = IpcMessage {
        version: 1,
        opcode: 1,
        nonce: 1,
        checksum: None,
        auth_tag: None,
        payload: vec![1, 2, 3],
    }
    .with_checksum()
    .with_auth(key);

    let target = route_with_quota(&msg, channel, 1, Some(key)).expect("route ok");
    assert_eq!(target, IpcTargetClass::Core);

    let replay = route_with_quota(&msg, channel, 2, Some(key));
    assert!(replay.is_err());

    let msg2 = IpcMessage {
        nonce: 2,
        ..msg.clone()
    };
    let _ = route_with_quota(&msg2, channel, 3, Some(key)).expect("route ok");

    let msg3 = IpcMessage {
        nonce: 3,
        ..msg.clone()
    };
    let quota = route_with_quota(&msg3, channel, 4, Some(key));
    assert!(quota.is_err());
}
