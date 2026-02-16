mod test_guard;
use redmi_ia::core::ipc::IPC;
use redmi_ia::core::ipc_tls_adapter::IPCTlsAdapter;
use redmi_ia::core::tls_client::TLSClient;
use redmi_ia::core::tls_integration::TLSIntegrationManager;
use std::sync::Arc;

#[test]
fn tls_adapter_backpressure_when_unauthenticated() {
    let tls = Arc::new(TLSIntegrationManager::new());
    let client = TLSClient::new(Arc::clone(&tls));
    let mut adapter = IPCTlsAdapter::new(client, 7, "tls");

    let mut ipc = IPC::new();
    ipc.register_channel("tls");
    ipc.subscribe(7, "tls");

    let _ = ipc.send(1, "tls", b"payload", 1).expect("send ok");
    ipc.route();
    let forwarded = adapter.pump(&mut ipc);
    assert_eq!(forwarded, 0);
    assert!(ipc.recv(7).is_some());
}

#[test]
fn tls_adapter_forwards_when_authenticated() {
    let tls = Arc::new(TLSIntegrationManager::new());
    let client = TLSClient::new(Arc::clone(&tls));
    let _ = client.authenticate_with_secret_vec("token_1234567890abcd".into(), vec![1u8; 16], 1);
    let mut adapter = IPCTlsAdapter::new(client, 7, "tls");

    let mut ipc = IPC::new();
    ipc.register_channel("tls");
    ipc.subscribe(7, "tls");

    let _ = ipc.send(1, "tls", b"payload", 1).expect("send ok");
    ipc.route();
    let forwarded = adapter.pump(&mut ipc);
    assert_eq!(forwarded, 1);
    assert!(ipc.recv(7).is_none());
}
