
use anyhow::Result;
#[cfg(feature = "real_tls")]
use log::{info, warn};
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(feature = "real_tls")]
use alloc::collections::BTreeMap;
use crossbeam_queue::SegQueue;
use sha2::{Digest, Sha256};
use secrecy::ExposeSecret;

#[cfg(feature = "real_tls")]
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
#[cfg(feature = "real_tls")]
use crate::server::TLSServer;
use crate::client::TLSClient;
use crate::api::token::TokenManager;
#[cfg(feature = "real_tls")]
use crate::kernel_interface;
#[cfg(feature = "real_tls")]
use crate::services::{ApiGateway, ModuleBundle};
use crate::security::SecretProvider;

#[cfg(feature = "real_tls")]
use std::thread;
#[cfg(feature = "real_tls")]
use std::time::Duration;
use crate::runtime::loops::sandbox::{set_tls_sandbox_active, SandboxLimits, SandboxManager, SandboxPolicy};

#[cfg(feature = "real_tls")]
fn bundle_payload(bundle: &crate::services::ModuleBundle) -> Vec<u8> {
    serde_json::to_vec(bundle).unwrap_or_default()
}

#[cfg(feature = "real_tls")]
fn gateway_nonce() -> String {
    let mut bytes = [0u8; 16];
    let _ = crate::rng::kernel_rng_fill(&mut bytes);
    crate::utils::hex_encode(&bytes)
}

#[cfg(feature = "real_tls")]
fn handle_ia_bundle_requests(
    gateway: &Arc<ApiGateway>,
    sl: &Arc<SecondaryLoop>,
    ia_token: &str,
    gateway_rx: &Arc<SegQueue<crate::runtime::loops::secondary_loop::SecondaryMessage>>,
    default_ttl: u64,
) {
    while let Some(msg) = gateway_rx.pop() {
        if let Some(plain) = sl.decrypt_message(msg.payload) {
            if let Ok(text) = core::str::from_utf8(&plain) {
                let trimmed = text.trim();
                if trimmed.contains("invalid") || trimmed.contains("expired") {
                    warn!("IA rejected bundle: {trimmed}");
                    deliver_ia_bundle(gateway, sl, ia_token, None, default_ttl);
                    sl.lock_ia();
                    continue;
                }
            }
            match gateway.handle_bundle_request(&plain, default_ttl) {
                Ok(resp) => match sl.send_message("tls_gateway", "ia_node", resp, ia_token) {
                    Ok(_) => {
                        info!("IA bundle_request acknowledged, IA sandbox unlocked");
                        sl.unlock_ia();
                    }
                    Err(err) => {
                        warn!("failed to deliver bundle to IA: {err}");
                        sl.lock_ia();
                    }
                },
                Err(err) => {
                    warn!("failed to build IA bundle response: {err}");
                    sl.lock_ia();
                }
            }
        }
    }
}

#[cfg(feature = "real_tls")]
const KERNEL_BUNDLE_TTL_SECS: u64 = 3600;
#[cfg(feature = "real_tls")]
const IA_BUNDLE_TTL_SECS: u64 = 3600;

#[cfg(feature = "real_tls")]
fn handle_tls_payload(sl: &Arc<SecondaryLoop>, payload: Vec<u8>, ia_token: &str) -> bool {
    sl.send_message("tls_gateway", "ia_node", payload, ia_token).is_ok()
}

#[cfg(feature = "real_tls")]
fn send_bundle_to_ia(
    gateway: &ApiGateway,
    sl: &Arc<SecondaryLoop>,
    ia_token: &str,
    bundle: &ModuleBundle,
) -> bool {
    let payload = gateway.format_bundle(bundle).into_bytes();
    if handle_tls_payload(sl, payload, ia_token) {
        info!("IA bundle delivered");
        true
    } else {
        warn!("failed to deliver IA bundle");
        false
    }
}

#[cfg(feature = "real_tls")]
fn deliver_ia_bundle(
    gateway: &ApiGateway,
    sl: &Arc<SecondaryLoop>,
    ia_token: &str,
    bundles: Option<&BTreeMap<String, ModuleBundle>>,
    ttl_secs: u64,
) {
    if let Some(bundle_map) = bundles {
        if let Some(bundle) = bundle_map.get("ia") {
            if send_bundle_to_ia(gateway, sl, ia_token, bundle) {
                return;
            }
            warn!("existing IA bundle rejected, reissuing");
        }
    }

    if let Ok(bundle) = gateway.module_bundle("ia", ttl_secs) {
        if send_bundle_to_ia(gateway, sl, ia_token, &bundle) {
            return;
        }
        warn!("reissued IA bundle rejected");
    } else {
        warn!("failed to generate IA bundle for delivery");
    }

    warn!("IA bundle delivery failed after retries");
}

#[cfg(feature = "real_tls")]
fn try_kernel_delivery(gateway: &ApiGateway, bundle: &ModuleBundle) -> Result<(), &'static str> {
    let payload = gateway.format_bundle(bundle).into_bytes();
    kernel_interface::on_tls_bundle(&payload)
}

#[cfg(feature = "real_tls")]
fn send_kernel_bundle(gateway: &ApiGateway, bundle: &ModuleBundle, ttl_secs: u64) -> bool {
    if try_kernel_delivery(gateway, bundle).is_ok() {
        info!("kernel bundle accepted");
        return true;
    }

    warn!("kernel bundle rejected, attempting reissue");

    if let Ok(reissued) = gateway.module_bundle("kernel", ttl_secs) {
        if try_kernel_delivery(gateway, &reissued).is_ok() {
            info!("kernel bundle reissued and accepted");
            return true;
        }
        warn!("kernel reissue was rejected");
    }

    if gateway.rollback_ticket_key() {
        warn!("rolled back TLS ticket key after kernel bundle failure");
    }

    false
}

#[cfg(feature = "real_tls")]
fn maybe_send_kernel_bundle(
    gateway: &ApiGateway,
    bundles: &BTreeMap<String, ModuleBundle>,
    ttl_secs: u64,
) {
    if let Some(bundle) = bundles.get("kernel") {
        if send_kernel_bundle(gateway, bundle, ttl_secs) {
            return;
        }
    } else if let Ok(bundle) = gateway.module_bundle("kernel", ttl_secs) {
        if send_kernel_bundle(gateway, &bundle, ttl_secs) {
            return;
        }
    }

    warn!("kernel bundle could not be issued");
}

#[cfg(feature = "real_tls")]
fn distribute_gateway_bundles(
    bundles: &BTreeMap<String, crate::services::ModuleBundle>,
    sm: &Arc<SessionManager>,
    il: &Arc<crate::runtime::loops::primary_loop::PrimaryLoop>,
    sl: &Arc<SecondaryLoop>,
    tl: &Arc<ThirdLoop>,
    fl: &Arc<ForthLoop>,
    el: &Arc<ExternalLoop>,
    gateway: &ApiGateway,
) -> Result<()> {
    let os_token = sm.get_session(ComponentType::OS, 0)?.token.token_value;
    let di_token = sm.get_session(ComponentType::DeviceInterfaces, 0)?.token.token_value;
    let display_token = sm.get_session(ComponentType::Display, 0)?.token.token_value;
    let power_token = sm.get_session(ComponentType::Power, 0)?.token.token_value;
    let network_token = sm.get_session(ComponentType::Network, 0)?.token.token_value;
    let messaging_token = sm.get_session(ComponentType::Messaging, 0)?.token.token_value;
    let calling_token = sm.get_session(ComponentType::Calling, 0)?.token.token_value;
    let kernel_token = sm.get_session(ComponentType::Kernel, 0)?.token.token_value;

    if let Some(bundle) = bundles.get("os") {
        let _ = sl.send_message("tls_gateway", "os_node", bundle_payload(bundle), &os_token);
    }

    if let Some(bundle) = bundles.get("device_interfaces") {
        let _ = tl.send_message("tls_gateway", "io_node", bundle_payload(bundle), &di_token);
    }

    if let Some(bundle) = bundles.get("display") {
        let _ = tl.send_message("tls_gateway", "ui_node", bundle_payload(bundle), &display_token);
    }

    if let Some(bundle) = bundles.get("audio") {
        let _ = tl.send_message("tls_gateway", "io_node", bundle_payload(bundle), &di_token);
    }

    if let Some(bundle) = bundles.get("power") {
        let _ = fl.send_message("tls_gateway", "power_node", bundle_payload(bundle), &power_token);
    }

    if let Some(bundle) = bundles.get("network") {
        let _ = el.send_message("tls_gateway", "network_node", bundle_payload(bundle), &network_token);
    }

    if let Some(bundle) = bundles.get("messaging") {
        let _ = el.send_message("tls_gateway", "sms_node", bundle_payload(bundle), &messaging_token);
    }

    if let Some(bundle) = bundles.get("calling") {
        let _ = el.send_message("tls_gateway", "call_node", bundle_payload(bundle), &calling_token);
    }

    if let Some(bundle) = bundles.get("tls") {
        let _ = il.send_message("tls_gateway", "server", bundle_payload(bundle), &kernel_token);
    }

    Ok(())
}

pub fn start() -> Result<()> {
    #[cfg(not(feature = "real_tls"))]
    crate::callbacks::require_callbacks_initialized();

    #[cfg(feature = "real_tls")]
    let (cfg, cfg_full, cert_bytes, key_bytes, loaded_cert, loaded_key, yaml_path, cert_path, key_path) = {
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
        (
            cfg,
            cfg_full,
            cert_bytes,
            key_bytes,
            loaded_cert,
            loaded_key,
            yaml_path,
            cert_path,
            key_path,
        )
    };

    #[cfg(feature = "real_tls")]
    let master_key = {
        let secret_provider = SecretProvider::init_from_secure_element()
            .map_err(|err| anyhow::anyhow!("failed to load runtime secrets: {err}"))?;
        secret_provider.master_key().expose_secret().to_string()
    };

    #[cfg(not(feature = "real_tls"))]
    let master_key = {
        let secret_provider = SecretProvider::init_from_secure_element()
            .map_err(|err| anyhow::anyhow!("failed to load runtime secrets: {err}"))?;
        secret_provider.master_key().expose_secret().to_string()
    };

    #[cfg(feature = "real_tls")]
    let boot_token = cfg.boot_token.as_deref().ok_or_else(|| anyhow::anyhow!("boot_token manquant"))?.to_string();

    #[cfg(not(feature = "real_tls"))]
    let boot_token = crate::utils::config::get_boot_token()
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .unwrap_or_else(|| derive_boot_token(&master_key));

    let tm = Arc::new(TokenManager::new(&master_key, &boot_token));

    let tls_sandbox_manager = SandboxManager::new();
    let _tls_sandbox = tls_sandbox_manager.create_sandbox(
        ComponentType::Custom(0x544c53),
        SandboxPolicy::for_os(),
        SandboxLimits::new_moderate(),
    );
    _tls_sandbox.activate();
    set_tls_sandbox_active(true);

    let ck = Arc::new(CryptoKey::new(&master_key, "primary_loop_context")?);
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

    let sm = Arc::new(SessionManager::new(&master_key, 300, 3600));
    
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
    #[cfg(feature = "real_tls")]
    let _ia_session = sm.open_session(ComponentType::IA, 0, None)?;
    #[cfg(feature = "real_tls")]
    let ia_token = sm.get_session(ComponentType::IA, 0)?.token.token_value;
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
    let tx_tls_gateway = Arc::new(SegQueue::new());
    sl.register_node("os_node", tx_os.clone());
    sl.register_node("ia_node", tx_ia.clone());
    sl.register_node("tls_gateway", tx_tls_gateway.clone());
    sl.lock_ia();

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

    #[cfg(feature = "real_tls")]
    let _api_gateway = {
            let gateway = Arc::new(ApiGateway::from_api_dir(&master_key, "configs/api")?);
        let bundles = gateway.rotate_keys_and_issue(300, 3600);

        distribute_gateway_bundles(&bundles, &sm, &il, &sl, &tl, &fl, &el, &gateway)?;
        deliver_ia_bundle(&gateway, &sl, &ia_token, Some(&bundles), IA_BUNDLE_TTL_SECS);
        maybe_send_kernel_bundle(&gateway, &bundles, KERNEL_BUNDLE_TTL_SECS);

        if let Some((_module, bundle)) = bundles.iter().next() {
            if let Some(route_id) = bundle.routes.first() {
                let nonce = gateway_nonce();
                let _resolved = gateway.verify_and_resolve(route_id, &bundle.ticket, &nonce)?;
            }
        }

        let rotation_gateway = Arc::clone(&gateway);
        let rotation_sm = Arc::clone(&sm);
        let rotation_il = Arc::clone(&il);
        let rotation_sl = Arc::clone(&sl);
        let rotation_tl = Arc::clone(&tl);
        let rotation_fl = Arc::clone(&fl);
        let rotation_el = Arc::clone(&el);
        let rotation_rx = Arc::clone(&tx_tls_gateway);
        let rotation_ia_token = ia_token.clone();

        thread::spawn(move || loop {
            handle_ia_bundle_requests(
                &rotation_gateway,
                &rotation_sl,
                &rotation_ia_token,
                &rotation_rx,
                3600,
            );
            thread::sleep(Duration::from_millis(50));
        });

        thread::spawn(move || {
            let mut prev = rotation_gateway.metrics_snapshot();
            loop {
            thread::sleep(Duration::from_secs(3600));
            let bundles = rotation_gateway.rotate_keys_and_issue(300, 3600);
            let _ = distribute_gateway_bundles(
                &bundles,
                &rotation_sm,
                &rotation_il,
                &rotation_sl,
                &rotation_tl,
                &rotation_fl,
                &rotation_el,
                &rotation_gateway,
            );
            deliver_ia_bundle(&rotation_gateway, &rotation_sl, &rotation_ia_token, Some(&bundles), IA_BUNDLE_TTL_SECS);
            maybe_send_kernel_bundle(&rotation_gateway, &bundles, KERNEL_BUNDLE_TTL_SECS);

            let after = rotation_gateway.metrics_snapshot();
            let delta_denied = after.total_denied.saturating_sub(prev.total_denied);
            let delta_success = after.total_success.saturating_sub(prev.total_success);

            if delta_denied > 50 && delta_denied > delta_success.saturating_mul(2) {
                if rotation_gateway.rollback_ticket_key() {
                    let bundles = rotation_gateway.issue_bundles(3600);
                    let _ = distribute_gateway_bundles(
                        &bundles,
                        &rotation_sm,
                        &rotation_il,
                        &rotation_sl,
                        &rotation_tl,
                        &rotation_fl,
                        &rotation_el,
                        &rotation_gateway,
                    );
                    deliver_ia_bundle(&rotation_gateway, &rotation_sl, &rotation_ia_token, Some(&bundles), IA_BUNDLE_TTL_SECS);
                    maybe_send_kernel_bundle(&rotation_gateway, &bundles, KERNEL_BUNDLE_TTL_SECS);
                }
            }

            prev = after;
            }
        });

        gateway
    };

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

    #[cfg(feature = "real_tls")]
    {
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
    }

    let client = TLSClient::new(il.clone(), Some(tm.clone()));
    let tx_ok = client.transmit("server", good_token.clone().into_bytes());
    if tx_ok.is_err() {
    }
    let _client_locked = client.is_locked();

    #[cfg(feature = "real_tls")]
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

fn derive_boot_token(master_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(master_key.as_bytes());
    let digest = hasher.finalize();
    crate::utils::hex_encode(&digest[..])
}

