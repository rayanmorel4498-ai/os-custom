
use anyhow::Result;
use alloc::sync::Arc;
use alloc::string::ToString;
use alloc::vec::Vec;
use crossbeam_queue::SegQueue;

use crate::config::TlsConfig;
use crate::crypto::CryptoKey;
use crate::honeypot::HoneypotSystem;
use crate::primary_loop::{PrimaryChannel};
use crate::secondary_loop::SecondaryLoop;
use crate::third_loop::ThirdLoop;
use crate::forth_loop::ForthLoop;
use crate::external_loop::ExternalLoop;
use crate::session_manager::SessionManager;
use crate::component_token::ComponentType;
use crate::heartbeat::HeartbeatMonitor;
use crate::server::TLSServer;
use crate::client::TLSClient;
use crate::api::token::TokenManager;
use crate::runtime::loops::sandbox::{set_tls_sandbox_active, SandboxLimits, SandboxManager, SandboxPolicy};

pub fn start() -> Result<()> {
    let yaml_path = "configs/default.yaml";
    let cert_path = "configs/cert.pem";
    let key_path = "configs/key.pem";

    let cfg = TlsConfig::load_from_yaml(yaml_path)?;
    let (cfg_full, cert_bytes, key_bytes) = TlsConfig::load_full(yaml_path, cert_path, key_path)?;
    let file_bytes = crate::config::load_file_bytes(cert_path)?;
    let (loaded_cert, loaded_key) = crate::config::load_cert_and_key(cert_path, key_path)?;
    if cert_bytes.len() != loaded_cert.len() {
    }
    if key_bytes.len() != loaded_key.len() {
    }
    if file_bytes.len() != loaded_cert.len() {
    }

    let master_key = cfg.master_key.as_deref().ok_or_else(|| anyhow::anyhow!("master_key manquant"))?;
    let boot_token = cfg.boot_token.as_deref().ok_or_else(|| anyhow::anyhow!("boot_token manquant"))?;

    let tm = Arc::new(TokenManager::new(master_key, boot_token));

    let tls_sandbox_manager = SandboxManager::new();
    let _tls_sandbox = tls_sandbox_manager.create_sandbox(
        ComponentType::Custom(0x544c53),
        SandboxPolicy::for_os(),
        SandboxLimits::new_moderate(),
    );
    _tls_sandbox.activate();
    set_tls_sandbox_active(true);

    let ck = Arc::new(CryptoKey::new(master_key, "primary_loop_context")?);
    let pt = b"payload-for-encrypt";
    let tok_enc = ck.encrypt(pt)?;
    let tok_dec = ck.decrypt(&tok_enc).expect("decrypt failed");
    if tok_dec != pt {
    }

    let hp = Arc::new(HoneypotSystem::new(tm.clone())?);
    hp.add_honeypots_batch(5);
    hp.shuffle_tokens();
    let count_before = hp.count();
    if count_before < 5 {
    }

    let hp_daemon = hp.clone();

    let sm = Arc::new(SessionManager::new(master_key, 300, 3600));
    
    let hb_monitor = Arc::new(HeartbeatMonitor::new(sm.clone(), 60, 30));
    
    let _kernel_session = sm.open_session(ComponentType::Kernel, 0, None)?;
    
    let _cpu_session = sm.open_session(ComponentType::CPU, 0, None)?;
    let _gpu_session = sm.open_session(ComponentType::GPU, 0, None)?;
    let _ram_session = sm.open_session(ComponentType::RAM, 0, None)?;
    
    let il = Arc::new(crate::runtime::loops::primary_loop::PrimaryLoop::new(
        sm.clone(),
        ck.clone(),
        hp_daemon.clone(),
        master_key.to_string(),
    ));
    
    il.init_kernel_and_hardware()
        .map_err(|e| anyhow::anyhow!("Failed to init kernel and hardware: {}", e))?;
    let _kernel = il.get_kernel_session()
        .map_err(|e| anyhow::anyhow!("Failed to get kernel session: {}", e))?;
    let _hardware = il.get_hardware_sessions();
    il.sync_sandbox_state();

    let _os_session = sm.open_session(ComponentType::OS, 0, None)?;
    let _ia_session = sm.open_session(ComponentType::IA, 0, None)?;
    let sl = Arc::new(SecondaryLoop::new(
        sm.clone(),
        ck.clone(),
        hp_daemon.clone(),
    ));
    sl.sync_sandbox_state();

    let _di_session = sm.open_session(ComponentType::DeviceInterfaces, 0, None)?;
    let _display_session = sm.open_session(ComponentType::Display, 0, None)?;
    let _audio_session = sm.open_session(ComponentType::Audio, 0, None)?;
    let tl = Arc::new(ThirdLoop::new(
        sm.clone(),
        ck.clone(),
        hp_daemon.clone(),
    ));
    tl.sync_sandbox_state();

    let _power_session = sm.open_session(ComponentType::Power, 0, None)?;
    let fl = Arc::new(ForthLoop::new(
        sm.clone(),
        ck.clone(),
        hp_daemon.clone(),
    ));
    fl.sync_sandbox_state();

    let _network_session = sm.open_session(ComponentType::Network, 0, None)?;
    let _messaging_session = sm.open_session(ComponentType::Messaging, 0, None)?;
    let _calling_session = sm.open_session(ComponentType::Calling, 0, None)?;
    let el = Arc::new(ExternalLoop::new(
        sm.clone(),
        ck.clone(),
        hp_daemon.clone(),
    ));
    el.sync_sandbox_state();

    let rx_server = Arc::new(SegQueue::new());
    let server_channel = PrimaryChannel::new("server".to_string(), il.clone(), rx_server.clone());
    il.register_node("server", rx_server.clone())
        .map_err(|e| anyhow::anyhow!("register_node server failed: {}", e))?;

    let tx_os = Arc::new(SegQueue::new());
    let tx_ia = Arc::new(SegQueue::new());
    sl.register_node("os_node", tx_os.clone());
    sl.register_node("ia_node", tx_ia.clone());

    let tx_io = Arc::new(SegQueue::new());
    let tx_ui = Arc::new(SegQueue::new());
    tl.register_node("io_node", tx_io.clone());
    tl.register_node("ui_node", tx_ui.clone());

    let tx_pwr = Arc::new(SegQueue::new());
    fl.register_node("power_node", tx_pwr.clone());

    let tx_net = Arc::new(SegQueue::new());
    let tx_sms = Arc::new(SegQueue::new());
    let tx_call = Arc::new(SegQueue::new());
    el.register_node("network_node", tx_net.clone());
    el.register_node("sms_node", tx_sms.clone());
    el.register_node("call_node", tx_call.clone());

    let primary_nodes = il.list_nodes();
    let secondary_nodes = sl.list_nodes();
    let third_nodes = tl.list_nodes();
    let forth_nodes = fl.list_nodes();
    let external_nodes = el.list_nodes();

    if !primary_nodes.contains(&"server".to_string()) {
    }
    if !secondary_nodes.contains(&"os_node".to_string()) || !secondary_nodes.contains(&"ia_node".to_string()) {
    }
    if !third_nodes.contains(&"io_node".to_string()) || !third_nodes.contains(&"ui_node".to_string()) {
    }
    if !forth_nodes.contains(&"power_node".to_string()) {
    }
    if !external_nodes.contains(&"network_node".to_string()) || !external_nodes.contains(&"sms_node".to_string()) {
    }

    let kernel_session = sm.get_session(ComponentType::Kernel, 0)?;
    let good_token = kernel_session.token.token_value.clone();
    let bad_token = "totally_invalid_token";
    if !il.is_kernel_or_hardware_token(&good_token) {
    }
    if il.is_kernel_or_hardware_token(bad_token) {
    }

    let rx1 = Arc::new(SegQueue::new());
    let ch1 = PrimaryChannel::new("node1".to_string(), il.clone(), rx1.clone());
    il.register_node("node1", rx1.clone())
        .map_err(|e| anyhow::anyhow!("register_node node1 failed: {}", e))?;
    let nodes = il.list_nodes();
    if !nodes.contains(&"node1".to_string()) {
    }

    let payload = b"internal message body".to_vec();
    let send_ok = ch1.send("server", payload.clone(), &good_token);
    if !send_ok {
    }

    let recv_payload = match server_channel.recv() {
        Some(p) => p,
        None => {
            Vec::new()
        }
    };
    if recv_payload != payload {
    }

    let external_token_bytes = good_token.clone().into_bytes();
    let receive_res = il.receive_external_token("server", external_token_bytes);
    if receive_res.is_err() {
    }
    let bad_receive = il.receive_external_token("server", b"badutf\xFF".to_vec());
    if bad_receive.is_ok() {
    }

    let server_channel_clone = server_channel.clone();
    let server = TLSServer::new(
        &ck,
        server_channel_clone,
        yaml_path,
        cert_path,
        key_path,
    )?;

    let server_for_run = server.clone();
    server_for_run.run_once();

    let locked = server.is_locked();
    let _ = locked;

    server.reload_secrets(cert_path, key_path)?;

    let cert_len = server.with_cert(|c| c.len());
    let key_len = server.with_key(|k| k.len());
    if cert_len != loaded_cert.len() {
    }
    if key_len != loaded_key.len() {
    }

    let client = TLSClient::new(il.clone(), Some(tm.clone()));
    let tx_ok = client.transmit("server", good_token.clone().into_bytes());
    if tx_ok.is_err() {
    }
    let _client_locked = client.is_locked();

    let _cfg_present = cfg_full.master_key.is_some() || cfg_full.boot_token.is_some();
    let _nodes_count = il.list_nodes().len();
    let _hp_count = hp.count();
    
    let health = hb_monitor.health_check();
    if !health.is_healthy {
    }
    let session_summary = hb_monitor.session_summary();
    if session_summary.is_empty() {
    }

    Ok(())
}

