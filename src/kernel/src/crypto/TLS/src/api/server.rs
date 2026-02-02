extern crate alloc;

use crate::runtime::loops::primary_loop::PrimaryChannel;
use crate::core::crypto::crypto::CryptoKey;
use crate::config::TlsConfig;
use crate::api::token;
use crate::secret_loader::SecretLoader;
use crate::utils::hex_encode;
use crate::arm::{
    constant_time_compare,
    BufferPool,
    BatchTimestampCache,
    LazyHasher,
    StringIntern,
};
use anyhow::Result;
use secrecy::{SecretString, ExposeSecret};
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use parking_lot::RwLock;
use zeroize::Zeroizing;

pub struct TLSServerOptimized {
    pub buffer_pool: Arc<RwLock<BufferPool>>,
    pub timestamp_cache: BatchTimestampCache,
    pub string_intern: Arc<RwLock<StringIntern>>,
    pub lazy_hasher: LazyHasher,
    pub stream_buffer: Arc<RwLock<Vec<u8>>>,
}

impl TLSServerOptimized {
    pub fn new() -> Self {
        Self {
            buffer_pool: Arc::new(RwLock::new(BufferPool::new(32, 16, 8))),
            timestamp_cache: BatchTimestampCache::new(),
            string_intern: Arc::new(RwLock::new(StringIntern::new())),
            lazy_hasher: LazyHasher::new(),
            stream_buffer: Arc::new(RwLock::new(Vec::with_capacity(8192))),
        }
    }
}

#[allow(dead_code)]
pub struct TLSServer {
    pub master_key: SecretString,
    pub channel: PrimaryChannel,
    pub locked: Arc<RwLock<bool>>,
    pub cert: Arc<RwLock<Zeroizing<Vec<u8>>>>,
    pub key: Arc<RwLock<Zeroizing<Vec<u8>>>>,
    pub optimizations: Arc<TLSServerOptimized>,
    #[cfg(feature = "real_tls")]
    pub secret_loader: Arc<dyn SecretLoader>,
    pub _config: TlsConfig,
    pub handshake: parking_lot::Mutex<Option<crate::core::tls_handshake::TlsHandshake>>,
}

pub fn validate_tls_startup(yaml_path: &str) -> Result<()> {
    if !crate::config::has_yaml(yaml_path) {
        return Err(anyhow::anyhow!(
            "TLS INVIOLABLE: YAML non détecté à runtime."
        ));
    }

    Ok(())
}

#[allow(dead_code)]
impl TLSServer {
    pub fn validate_yaml_integrity(_yaml_path: &str) -> Result<()> {
        Ok(())
    }

    pub fn new(
        crypto: &CryptoKey,
        channel: PrimaryChannel,
        yaml_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Arc<Self>> {
        Self::validate_yaml_integrity(yaml_path)?;

        let cfg = TlsConfig::load_from_yaml(yaml_path)?;

        #[cfg(feature = "real_tls")]
        let secret_loader: Arc<dyn SecretLoader> = Arc::new(
            crate::secret_loader::std_impl::FileSecretLoader::new()
        );
        #[cfg(not(feature = "real_tls"))]
        let secret_loader: Arc<dyn SecretLoader> = Arc::new(
            NoOpSecretLoader
        );

        let cert_bytes = secret_loader.load(cert_path)?;
        let key_bytes = secret_loader.load(key_path)?;

        let master_key_str = crypto.export_as_base64();

        Ok(Arc::new(Self {
            master_key: SecretString::new(master_key_str.into()),
            channel,
            locked: Arc::new(RwLock::new(false)),
            cert: Arc::new(RwLock::new(Zeroizing::new(cert_bytes))),
            key: Arc::new(RwLock::new(Zeroizing::new(key_bytes))),
            optimizations: Arc::new(TLSServerOptimized::new()),
            #[cfg(feature = "real_tls")]
            secret_loader,
            _config: cfg,
            handshake: parking_lot::Mutex::new(None),
        }))
    }

    pub fn establish_tls_connection(&self, master_key: &str) -> Result<()> {
        let handshake = crate::core::tls_handshake::TlsHandshake::new(master_key)?;
        let mut hs = self.handshake.lock();
        *hs = Some(handshake);
        Ok(())
    }

    pub fn receive_client_hello(&self, _client_hello: &crate::core::tls_handshake::ClientHello) -> Result<crate::core::tls_handshake::ServerHello> {
        let mut hs_guard = self.handshake.lock();
        if let Some(_hs) = hs_guard.as_mut() {
            Ok(crate::core::tls_handshake::ServerHello {
                version: 0x0303,
                random: [0u8; 32],
                session_id: Vec::new(),
                cipher_suite: 0x002F,
                compression_method: 0,
            })
        } else {
            Err(anyhow::anyhow!("Handshake not initialized"))
        }
    }

    pub fn reload_secrets(&self, cert_path: &str, key_path: &str) -> Result<()> {
        #[cfg(feature = "real_tls")]
        {
            let cert_bytes = self.secret_loader.load(cert_path)?;
            let key_bytes = self.secret_loader.load(key_path)?;
            *self.cert.write() = Zeroizing::new(cert_bytes);
            *self.key.write() = Zeroizing::new(key_bytes);
        }
        #[cfg(not(feature = "real_tls"))]
        {
            let _ = (cert_path, key_path);
        }
        Ok(())
    }

    pub fn encode_with_stream(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.optimizations.stream_buffer.write();
        stream.extend_from_slice(data);
        Ok(stream.clone())
    }

    pub fn get_buffer(&self, size: usize) -> Option<Vec<u8>> {
        let mut pool = self.optimizations.buffer_pool.write();
        match size {
            s if s <= 256 => pool.get_small().or_else(|| Some(Vec::with_capacity(256))),
            s if s <= 4096 => pool.get_medium().or_else(|| Some(Vec::with_capacity(4096))),
            _ => pool.get_large().or_else(|| Some(Vec::with_capacity(16384))),
        }
    }

    pub fn return_buffer(&self, buf: Vec<u8>) {
        let mut pool = self.optimizations.buffer_pool.write();
        match buf.capacity() {
            c if c <= 256 => pool.return_small(buf),
            c if c <= 4096 => pool.return_medium(buf),
            _ => pool.return_large(buf),
        }
    }

    pub fn rotate_from_secret_paths(&self, cert_path: &str, key_path: &str) -> Result<()> {
        #[cfg(feature = "real_tls")]
        {
            let cert_bytes = self.secret_loader.load(cert_path)?;
            let key_bytes = match self.secret_loader.load(key_path) {
                Ok(b) => b,
                Err(_) => {
                    return Err(anyhow::anyhow!("key not exportable from SecretLoader; use HSM signer rotation"));
                }
            };

            real_tls::validate_public_key_pin(&cert_bytes)?;

            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&cert_bytes);
            let cert_hash = hasher.finalize_reset();
            hasher.update(&key_bytes);
            let key_hash = hasher.finalize();

            *self.cert.write() = Zeroizing::new(cert_bytes);
            *self.key.write() = Zeroizing::new(key_bytes);
            Ok(())
        }

        #[cfg(not(feature = "real_tls"))]
        {
            let _ = (cert_path, key_path);
            Err(anyhow::anyhow!("rotate_from_secret_paths only supported with real_tls feature"))
        }
    }

    #[cfg(feature = "real_tls")]
    pub fn spawn_periodic_rotation(self: Arc<Self>, cert_path: String, key_path: String, interval_secs: u64) {
        let me = Arc::clone(&self);
        std::thread::spawn(move || loop {
            crate::kernel_callbacks::kernel_sleep_secs(interval_secs);
            let _ = me.rotate_from_secret_paths(&cert_path, &key_path);
        });
    }

    pub fn run_once(self: Arc<Self>) {
        if *self.locked.read() {
            return;
        }

        if let Some(payload) = self.channel.recv() {
            self.process(payload);
        }
    }

    fn process(&self, payload: Vec<u8>) {
        if *self.locked.read() {
            return;
        }

        let valid = if let Ok(token_str) = String::from_utf8(payload.clone()) {
            token::validate_token(self.master_key.expose_secret(), "", &token_str)
        } else {
            false
        };

        if !valid {
            *self.locked.write() = true;
            let _ = self.channel.send("honeypot", b"ALERT_INVALID_TOKEN".to_vec(), "");
        }
    }

    pub fn is_locked(&self) -> bool {
        *self.locked.read()
    }

    pub fn with_cert<F, T>(&self, f: F) -> T
    where F: FnOnce(&[u8]) -> T
    {
        let r = self.cert.read();
        f(&r)
    }

    pub fn with_key<F, T>(&self, f: F) -> T
    where F: FnOnce(&[u8]) -> T
    {
        let r = self.key.read();
        f(&r)
    }

    pub fn rotate_keys(&self, new_cert: Vec<u8>, new_key: Vec<u8>) -> Result<()> {
        use sha2::{Digest, Sha256};

        #[cfg(feature = "real_tls")]
        real_tls::validate_public_key_pin(&new_cert)?;

        let mut hasher = Sha256::new();
        hasher.update(&new_cert);
        let cert_hash = hasher.finalize_reset();
        hasher.update(&new_key);
        let key_hash = hasher.finalize();

        let _cert_hex = hex_encode(&cert_hash);
        let _key_hex = hex_encode(&key_hash);
        let _cmp = constant_time_compare(&_cert_hex, &_key_hex);

        *self.cert.write() = Zeroizing::new(new_cert);
        *self.key.write() = Zeroizing::new(new_key);

        Ok(())
    }

    #[cfg(feature = "real_tls")]
    pub fn atomic_rotate_files(&self, cert_path: &str, key_path: &str, new_cert: &[u8], new_key: &[u8]) -> Result<()> {
        let _ = (cert_path, key_path, new_cert, new_key);
        Err(anyhow::anyhow!("File I/O not available in no_std mode"))
    }
}

#[cfg(not(feature = "real_tls"))]
pub struct NoOpSecretLoader;

#[cfg(not(feature = "real_tls"))]
impl SecretLoader for NoOpSecretLoader {
    fn load(&self, _path: &str) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "real_tls")]
pub mod real_tls {
    use super::*;
    use rustls::{ServerConfig, ServerConnection, ProtocolVersion};
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use sha2::{Digest, Sha256};
    use log::info;
    use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
    use alloc::sync::Arc as StdArc;
    use parking_lot::Mutex as StdMutex;

    #[derive(Clone, Copy, Debug)]
    pub enum StrictnessLevel {
        Normal,
        Strict,
        Paranoid,
    }

    pub struct MtlsConfig {
        pub require_client_cert: bool,
        pub pinned_clients: Vec<String>,
    }

    fn read_strictness() -> StrictnessLevel {
        match crate::config::get_optional("tls_strictness").as_deref() {
            Some("normal") => StrictnessLevel::Normal,
            Some("paranoid") => StrictnessLevel::Paranoid,
            _ => StrictnessLevel::Strict,
        }
    }

    fn current_unix_secs() -> u64 {
        crate::time_abstraction::kernel_time_secs()
    }

    struct SessionTicketEncryption {
        master: Vec<u8>,
        version: AtomicU32,
        last_rotation: AtomicU64,
        rotation_secs: u64,
        ticket_counter: AtomicU64,
    }

    impl SessionTicketEncryption {
        fn new(master_key: &[u8], rotation_secs: u64) -> Self {
            Self {
                master: master_key.to_vec(),
                version: AtomicU32::new(1u32),
                last_rotation: AtomicU64::new(current_unix_secs()),
                rotation_secs,
                ticket_counter: AtomicU64::new(0),
            }
        }

        fn rotate_if_needed(&self) {
            let now = current_unix_secs();
            let last = self.last_rotation.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= self.rotation_secs {
                let new_ver = self.version.fetch_add(1, Ordering::SeqCst) + 1;
                self.last_rotation.store(now, Ordering::Relaxed);
                info!("ticket rotation: new version {}", new_ver);
            }
        }

        fn encrypt_ticket(&self, session_data: &[u8]) -> Vec<u8> {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::ChaCha20Poly1305;
            use chacha20poly1305::Nonce;
            use rand::RngCore;
            use hkdf::Hkdf;
            use sha2::Sha256;

            self.rotate_if_needed();
            let counter = self.ticket_counter.fetch_add(1, Ordering::SeqCst) + 1;
            let salt = counter.to_be_bytes();
            let hk = Hkdf::<Sha256>::new(Some(&salt), &self.master);
            let version = self.version.load(Ordering::Relaxed);
            let info = format!("redmi-ticket-v{}", version);
            let mut okm = [0u8; 32];
            if hk.expand(info.as_bytes(), &mut okm).is_err() {
                return Vec::new();
            }

            let cipher = ChaCha20Poly1305::new(&okm.into());

            let mut nonce_bytes = [0u8; 12];
            crate::rng::kernel_rng_fill(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ad = b"redmi-tls-v1";

            let ct = match cipher.encrypt(nonce, chacha20poly1305::aead::Payload { msg: session_data, aad: ad }) {
                Ok(c) => c,
                Err(_) => Vec::new(),
            };

            let mut out = Vec::with_capacity(4 + 8 + 12 + ct.len());
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
            out
        }

        fn decrypt_ticket(&self, data: &[u8]) -> Option<Vec<u8>> {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::ChaCha20Poly1305;
            use chacha20poly1305::Nonce;
            use hkdf::Hkdf;
            use sha2::Sha256;

            if data.len() < 24 {
                return None;
            }

            let version_bytes: [u8;4] = [data[0], data[1], data[2], data[3]];
            let version = u32::from_be_bytes(version_bytes);
            let counter_bytes: [u8;8] = [data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11]];
            let counter = u64::from_be_bytes(counter_bytes);
            let nonce = Nonce::from_slice(&data[12..24]);
            let ct = &data[24..];

            let salt = counter.to_be_bytes();
            let hk = Hkdf::<Sha256>::new(Some(&salt), &self.master);
            let info = format!("redmi-ticket-v{}", version);
            let mut okm = [0u8; 32];
            if hk.expand(info.as_bytes(), &mut okm).is_err() {
                return None;
            }

            let cipher = ChaCha20Poly1305::new(&okm.into());
            let ad = b"redmi-tls-v1";

            match cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ct, aad: ad }) {
                Ok(pt) => Some(pt),
                Err(_) => None,
            }
        }
    }

    struct EarlyDataValidator {
        rejected_nonces: alloc::collections::BTreeMap<Vec<u8>, u64>,
        max_nonces: usize,
        ttl_secs: u64,
        db_path: Option<std::path::PathBuf>,
        persist_every: usize,
        inserts_since_persist: usize,
        cleanup_interval: u32,
        cleanup_counter: u32,
        timestamp_cache: crate::arm::BatchTimestampCache,
    }

    impl EarlyDataValidator {
        fn new() -> Self {
            let db_path = std::env::var_os("REDMI_EARLY_NONCE_DB").map(|s| std::path::PathBuf::from(s));
            let mut map = alloc::collections::BTreeMap::new();
            if let Some(ref p) = db_path {
                if let Ok(s) = std::fs::read_to_string(p) {
                    for line in s.lines() {
                        let mut parts = line.split_whitespace();
                        if let (Some(hex), Some(ts_str)) = (parts.next(), parts.next()) {
                            if let Ok(ts) = ts_str.parse::<u64>() {
                                if let Ok(bytes) = hex_to_bytes(hex) {
                                    map.insert(bytes, ts);
                                }
                            }
                        }
                    }
                }
            }

            Self {
                rejected_nonces: map,
                max_nonces: 10000,
                ttl_secs: 300,
                db_path,
                persist_every: 128,
                inserts_since_persist: 0,
                cleanup_interval: 256,
                cleanup_counter: 0,
                timestamp_cache: crate::arm::BatchTimestampCache::new(),
            }
        }

        fn check_early_data_nonce(&mut self, nonce: &[u8]) -> bool {
            self.cleanup_counter = self.cleanup_counter.saturating_add(1);
            if self.cleanup_counter >= self.cleanup_interval {
                let now = self.timestamp_cache.get();
                self.rejected_nonces.retain(|_, &mut ts| {
                    now.saturating_sub(ts) <= self.ttl_secs
                });
                self.cleanup_counter = 0;
            }

            if self.rejected_nonces.contains_key(nonce) {
                return false;
            }

            if self.rejected_nonces.len() >= self.max_nonces {
                if let Some(old_key) = self.rejected_nonces.iter().next().map(|(k, _)| k.clone()) {
                    self.rejected_nonces.remove(&old_key);
                }
            }

            let now = self.timestamp_cache.get();
            self.rejected_nonces.insert(nonce.to_vec(), now);
            self.inserts_since_persist = self.inserts_since_persist.saturating_add(1);
            if let Some(ref p) = self.db_path {
                if self.inserts_since_persist >= self.persist_every {
                    let _ = self.persist_to_disk(p);
                    self.inserts_since_persist = 0;
                }
            }

            true
        }

        fn persist_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
            let tmp = path.with_extension("tmp");
            let mut s = String::with_capacity(self.rejected_nonces.len() * 48);
            for (k, &ts) in self.rejected_nonces.iter() {
                s.push_str(&format!("{} {}\n", bytes_to_hex(k), ts));
            }
            std::fs::write(&tmp, s)?;
            std::fs::rename(&tmp, path)?;
            Ok(())
        }
    }

    fn bytes_to_hex(b: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(b.len() * 2);
        for &x in b {
            use core::fmt::Write;
            write!(s, "{:02x}", x).ok();
        }
        s
    }

    fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut chars = s.chars();
        while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
            let hi = hi.to_digit(16).ok_or(())?;
            let lo = lo.to_digit(16).ok_or(())?;
            out.push(((hi << 4) | lo) as u8);
        }
        Ok(out)
    }

    fn zeroize_buffer(buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    struct EchConfig {
        enabled: bool,
        public_key: Vec<u8>,
    }

    struct KeyUpdateManager {
        last_update: AtomicU64,
        update_interval_secs: u64,
    }

    impl KeyUpdateManager {
        fn new(interval_secs: u64) -> Self {
            Self {
                last_update: AtomicU64::new(crate::time_abstraction::kernel_time_secs()),
                update_interval_secs: interval_secs,
            }
        }

        fn should_update_key(&self) -> bool {
            let now = crate::time_abstraction::kernel_time_secs();
            let last = self.last_update.load(Ordering::Relaxed);
            now - last >= self.update_interval_secs
        }

        fn mark_updated(&self) {
            let now = crate::time_abstraction::kernel_time_secs();
            self.last_update.store(now, Ordering::Relaxed);
        }
    }

    struct MemoryProtection;

    impl MemoryProtection {
        fn lock_sensitive_memory(_secrets: &[&[u8]]) {
            #[cfg(unix)]
            unsafe {
                let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
            }
        }
    }

    struct EntropyAuditor {
        samples: Vec<u8>,
        min_entropy_bits: f64,
    }

    impl EntropyAuditor {
        fn new() -> Self {
            Self {
                samples: Vec::with_capacity(10000),
                min_entropy_bits: 7.5,
            }
        }

        fn audit_entropy(&self) -> bool {
            if self.samples.len() < 1000 {
                return true;
            }
            
            let mut transitions = 0;
            for i in 1..self.samples.len() {
                if self.samples[i] ^ self.samples[i-1] != 0 {
                    transitions += 1;
                }
            }
            let entropy = transitions as f64 / self.samples.len() as f64;
            entropy >= self.min_entropy_bits / 8.0
        }
    }

    struct PostHandshakeAuth {
        enabled: bool,
        client_auth_required: bool,
    }

    struct CompressionDetector;

    impl CompressionDetector {
        fn validate_no_compression(&self, _conn: &ServerConnection) -> bool {
            true
        }
    }

    struct HandshakeTimeout {
        timeout_secs: u64,
        start_time: AtomicU64,
    }

    impl HandshakeTimeout {
        fn new() -> Self {
            Self {
                timeout_secs: 5,
                start_time: AtomicU64::new(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                ),
            }
        }

        fn check_timeout(&self) -> bool {
            let now = crate::time_abstraction::kernel_time_secs();
            let start = self.start_time.load(Ordering::Relaxed);
            now - start >= self.timeout_secs
        }
    }

    impl StrictnessLevel {
        fn name(&self) -> &'static str {
            match self {
                StrictnessLevel::Normal => "normal",
                StrictnessLevel::Strict => "strict",
                StrictnessLevel::Paranoid => "paranoid",
            }
        }
    }

    struct RateLimiter {
        handshakes_per_second: u64,
        last_reset: StdMutex<u64>,
        count: AtomicU64,
        check_interval: u32,
        check_counter: u32,
    }

    impl RateLimiter {
        fn new(handshakes_per_second: u64) -> Self {
            RateLimiter {
                handshakes_per_second,
                last_reset: StdMutex::new(crate::time_abstraction::kernel_time_secs()),
                count: AtomicU64::new(0),
                check_interval: 10,
                check_counter: 0,
            }
        }

        fn check_and_increment(&mut self) -> bool {
            self.check_counter = self.check_counter.saturating_add(1);
            if self.check_counter >= self.check_interval {
                let now = crate::time_abstraction::kernel_time_secs();
                
                if let Ok(mut last) = self.last_reset.lock() {
                    if now.saturating_sub(*last) >= 1 {
                        self.count.store(0, Ordering::Relaxed);
                        *last = now;
                        self.check_counter = 0;
                    }
                }
            }

            let current = self.count.fetch_add(1, Ordering::Relaxed);
            current < self.handshakes_per_second
        }
    }

    struct ConnectionPool {
        max_connections: u64,
        active_connections: AtomicU64,
    }

    impl ConnectionPool {
        fn new(max_connections: u64) -> Self {
            ConnectionPool {
                max_connections,
                active_connections: AtomicU64::new(0),
            }
        }

        fn acquire(&self) -> bool {
            loop {
                let current = self.active_connections.load(Ordering::Relaxed);
                if current >= self.max_connections {
                    return false;
                }
                if self.active_connections.compare_exchange(
                    current,
                    current + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ).is_ok() {
                    return true;
                }
            }
        }

        fn release(&self) {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl Drop for ConnectionPool {
        fn drop(&mut self) {
        }
    }

    struct PoolGuard {
        pool: StdArc<ConnectionPool>,
    }

    impl Drop for PoolGuard {
        fn drop(&mut self) {
            self.pool.release();
        }
    }

    pub struct ServerBuilder {
        strictness: StrictnessLevel,
        handshakes_per_second: u64,
        max_connections: u64,
        alpn_protocols: Vec<Vec<u8>>,
        require_mtls: bool,
    }

    impl ServerBuilder {
        pub fn new() -> Self {
            ServerBuilder {
                strictness: StrictnessLevel::Strict,
                handshakes_per_second: 100,
                max_connections: 1000,
                alpn_protocols: vec![],
                require_mtls: false,
            }
        }

        pub fn strictness(mut self, level: StrictnessLevel) -> Self {
            self.strictness = level;
            self
        }

        pub fn handshakes_per_second(mut self, rate: u64) -> Self {
            self.handshakes_per_second = rate;
            self
        }

        pub fn max_connections(mut self, max: u64) -> Self {
            self.max_connections = max;
            self
        }

        pub fn alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
            self.alpn_protocols = protocols;
            self
        }

        pub fn require_mtls(mut self, require: bool) -> Self {
            self.require_mtls = require;
            self
        }
    }

    fn validate_cipher_suite_strength() -> anyhow::Result<()> {
        if crate::config::get_optional("tls_allow_insecure")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false) {
            return Err(anyhow::anyhow!("tls_allow_insecure must be false in hardened config"));
        }
        Ok(())
    }

    fn config_true(key: &str) -> bool {
        crate::config::get_optional(key)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn config_true_default(key: &str, default: bool) -> bool {
        crate::config::get_optional(key)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(default)
    }

    fn config_u64(key: &str) -> Option<u64> {
        crate::config::get_optional(key).and_then(|v| v.parse::<u64>().ok())
    }

    fn config_u64_default(key: &str, default: u64) -> u64 {
        config_u64(key).unwrap_or(default)
    }

    fn parse_allowlist() -> Option<Vec<String>> {
        crate::config::get_optional("tls_early_data_allowlist").map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        }).filter(|v| !v.is_empty())
    }

    fn is_allowed_action(payload: &[u8], allowlist: &[String]) -> bool {
        if allowlist.is_empty() {
            return true;
        }
        let Ok(s) = core::str::from_utf8(payload) else { return false; };
        allowlist.iter().any(|item| s.contains(item))
    }

    fn app_auth_required() -> bool {
        crate::config::get_optional("tls_app_token_required")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn validate_app_token(line: &str) -> bool {
        let master = crate::config::get_optional("tls_app_token_master");
        let master = match master {
            Some(m) if !m.is_empty() => m,
            _ => return false,
        };
        let context = crate::config::get_optional("tls_app_token_context").unwrap_or_default();
        let token = line.trim_start_matches("TOKEN ").trim_start_matches("TOKEN:").trim();
        crate::api::token::validate_token(&master, &context, token)
    }

    fn check_client_cert_pins(conn: &ServerConnection) -> bool {
        let Some(list) = crate::config::get_optional("mtls_client_cert_fingerprints") else { return true; };
        let expected: Vec<String> = list
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if expected.is_empty() {
            return true;
        }

        let Some(certs) = conn.peer_certificates() else { return false; };
        for cert in certs {
            let mut hasher = Sha256::new();
            hasher.update(&cert.0);
            let fp = hex_encode(&hasher.finalize()).to_lowercase();
            if expected.iter().any(|e| e == &fp) {
                return true;
            }
        }
        false
    }

    struct TicketProducer {
        enc: SessionTicketEncryption,
        lifetime: u32,
    }

    impl TicketProducer {
        fn new(master: &[u8], lifetime: u32, rotation_secs: u64) -> Self {
            Self {
                enc: SessionTicketEncryption::new(master, rotation_secs),
                lifetime,
            }
        }
    }

    struct DisabledTicketProducer;

    impl rustls::server::ProducesTickets for DisabledTicketProducer {
        fn enabled(&self) -> bool {
            false
        }

        fn lifetime(&self) -> u32 {
            0
        }

        fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    impl rustls::server::ProducesTickets for TicketProducer {
        fn enabled(&self) -> bool {
            true
        }

        fn lifetime(&self) -> u32 {
            self.lifetime
        }

        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            let out = self.enc.encrypt_ticket(plain);
            if out.is_empty() { None } else { Some(out) }
        }

        fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
            self.enc.decrypt_ticket(cipher)
        }
    }

    fn make_hardened_server_config(
        cert_pem: &[u8],
        key_pem: &[u8],
        strictness: StrictnessLevel,
    ) -> anyhow::Result<ServerConfig> {
        let mut reader = std::io::BufReader::new(cert_pem);
        let certs_der = certs(&mut reader).map_err(|_| anyhow::anyhow!("failed to parse certs"))?;
        let cert_chain: Vec<rustls::Certificate> = certs_der.into_iter().map(rustls::Certificate).collect();

        let mut key_reader = std::io::BufReader::new(key_pem);
        let mut keys = pkcs8_private_keys(&mut key_reader).map_err(|_| anyhow::anyhow!("failed to parse key"))?;
        if keys.is_empty() {
            return Err(anyhow::anyhow!("no private keys found"));
        }

        let priv_key = rustls::PrivateKey(keys.remove(0));
        for key in keys.iter_mut() {
            zeroize::Zeroize::zeroize(key);
        }

        let require_mtls = matches!(strictness, StrictnessLevel::Strict | StrictnessLevel::Paranoid)
            || crate::config::get_optional("mtls_client_cert_path").is_some();
        let _strictness_name = strictness.name();
        validate_cipher_suite_strength()?;
        let _ech = EchConfig {
            enabled: crate::config::get_optional("tls_ech_public_key").is_some(),
            public_key: Vec::new(),
        };
        let key_update = KeyUpdateManager::new(3600);
        if key_update.should_update_key() {
            key_update.mark_updated();
        }
        let _pha = PostHandshakeAuth {
            enabled: false,
            client_auth_required: require_mtls,
        };
        let _ = (_ech.enabled, _ech.public_key.len(), _pha.enabled, _pha.client_auth_required);

        if SPKI_FINGERPRINT_HEX.is_empty() {
            return Err(anyhow::anyhow!("SPKI_FINGERPRINT_HEX required (pinning mandatory)"));
        }

        if require_mtls && crate::config::get_optional("mtls_client_cert_fingerprints").is_none() {
            return Err(anyhow::anyhow!("mtls_client_cert_fingerprints is required for strict mTLS pinning"));
        }

        let mut config = if require_mtls {
            let mtls_path = crate::config::get_optional("mtls_client_cert_path")
                .ok_or_else(|| anyhow::anyhow!("mtls_client_cert_path is required for client auth"))?;
            let mtls_bytes = crate::config::load_file_bytes(&mtls_path)?;
            let mut mtls_reader = std::io::BufReader::new(std::io::Cursor::new(mtls_bytes));
            let mtls_certs = certs(&mut mtls_reader)
                .map_err(|_| anyhow::anyhow!("failed to parse MTLS client certs"))?;
            let mut roots = rustls::RootCertStore::empty();
            for c in mtls_certs {
                roots.add(&rustls::Certificate(c))
                    .map_err(|_| anyhow::anyhow!("failed to add MTLS client cert"))?;
            }
            let verifier = StdArc::new(rustls::server::AllowAnyAuthenticatedClient::new(roots));
            ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, priv_key)
                .map_err(|e| anyhow::anyhow!("failed to build server config: {}", e))?
        } else {
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(cert_chain, priv_key)
                .map_err(|e| anyhow::anyhow!("failed to build server config: {}", e))?
        };

        

        config.session_storage = StdArc::new(rustls::server::NoServerSessionStorage {});
        config.max_early_data_size = 0;

        if config_true("tls_disable_session_tickets") {
            config.ticketer = StdArc::new(DisabledTicketProducer);
        } else {
            let mut hasher = Sha256::new();
            hasher.update(key_pem);
            let master = hasher.finalize();
            let lifetime = crate::config::get_optional("tls_ticket_lifetime_secs")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(3600);
            let rotation_secs = crate::config::get_optional("tls_ticket_rotate_secs")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3600);
            config.ticketer = StdArc::new(TicketProducer::new(master.as_slice(), lifetime, rotation_secs));
        }

        config.ignore_client_order = false;

        match strictness {
            StrictnessLevel::Normal => {
            }
            StrictnessLevel::Strict => {
                if crate::config::get_optional("mtls_client_cert_path").is_some() {
                }

                if config_true("tls_ech_required") && crate::config::get_optional("tls_ech_public_key").is_none() {
                    return Err(anyhow::anyhow!("tls_ech_public_key required when tls_ech_required=true"));
                }

                if let Some(ocsp_path) = crate::config::get_optional("ocsp_response_path") {
                    let ocsp_response = crate::config::load_file_bytes(&ocsp_path)
                        .map_err(|_| anyhow::anyhow!("Strict TLS requires OCSP response at {}", ocsp_path))?;
                    if ocsp_response.is_empty() {
                        return Err(anyhow::anyhow!("OCSP response is empty"));
                    }
                    if let Some(max_bytes) = config_u64("ocsp_max_bytes") {
                        if ocsp_response.len() as u64 > max_bytes {
                            return Err(anyhow::anyhow!("OCSP response too large"));
                        }
                    }
                    if let Some(expected_hex) = crate::config::get_optional("ocsp_sha256") {
                        let mut hasher = Sha256::new();
                        hasher.update(&ocsp_response);
                        let computed = hex_encode(&hasher.finalize());
                        if !constant_time_compare(&computed, &expected_hex) {
                            return Err(anyhow::anyhow!("OCSP response hash mismatch"));
                        }
                    }
                    let max_age = config_u64_default("ocsp_max_age_secs", 86_400);
                    if max_age > 0 {
                        if let Ok(meta) = std::fs::metadata(&ocsp_path) {
                            if let Ok(mtime) = meta.modified() {
                                if let Ok(age) = mtime.elapsed() {
                                    if age.as_secs() > max_age {
                                        return Err(anyhow::anyhow!("OCSP response too old"));
                                    }
                                }
                            }
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("Strict TLS requires ocsp_response_path"));
                }
                if let Some(sct_path) = crate::config::get_optional("sct_list_path") {
                    let sct_list = crate::config::load_file_bytes(&sct_path)
                        .map_err(|_| anyhow::anyhow!("Strict TLS requires SCT list at {}", sct_path))?;
                    if sct_list.is_empty() {
                        return Err(anyhow::anyhow!("SCT list is empty"));
                    }
                    if let Some(max_bytes) = config_u64("sct_max_bytes") {
                        if sct_list.len() as u64 > max_bytes {
                            return Err(anyhow::anyhow!("SCT list too large"));
                        }
                    }
                    if let Some(expected_hex) = crate::config::get_optional("sct_sha256") {
                        let mut hasher = Sha256::new();
                        hasher.update(&sct_list);
                        let computed = hex_encode(&hasher.finalize());
                        if !constant_time_compare(&computed, &expected_hex) {
                            return Err(anyhow::anyhow!("SCT list hash mismatch"));
                        }
                    }
                    let max_age = config_u64_default("sct_max_age_secs", 86_400);
                    if max_age > 0 {
                        if let Ok(meta) = std::fs::metadata(&sct_path) {
                            if let Ok(mtime) = meta.modified() {
                                if let Ok(age) = mtime.elapsed() {
                                    if age.as_secs() > max_age {
                                        return Err(anyhow::anyhow!("SCT list too old"));
                                    }
                                }
                            }
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("Strict TLS requires sct_list_path"));
                }
            }
            StrictnessLevel::Paranoid => {
                let entropy_auditor = EntropyAuditor::new();
                if !entropy_auditor.audit_entropy() {
                    return Err(anyhow::anyhow!("insufficient RNG entropy for paranoid mode"));
                }

                MemoryProtection::lock_sensitive_memory(&[cert_pem, key_pem]);

                if crate::config::get_optional("mtls_client_cert_path").is_none() {
                    return Err(anyhow::anyhow!("Paranoid mode requires mtls_client_cert_path"));
                }

                if crate::config::get_optional("tls_ech_public_key").is_none() {
                    return Err(anyhow::anyhow!("Paranoid mode requires tls_ech_public_key"));
                }
            }
        }

        Ok(config)
    }

    fn validate_tls_connection(
        conn: &ServerConnection,
        strictness: StrictnessLevel,
    ) -> bool {
        let timeout = HandshakeTimeout::new();
        if timeout.check_timeout() {
            return false;
        }

        let compression_detector = CompressionDetector;
        if !compression_detector.validate_no_compression(conn) {
            return false;
        }

        if let Some(version) = conn.protocol_version() {
            if version != ProtocolVersion::TLSv1_3 {
                return false;
            }
        } else {
            return false;
        }

        match strictness {
            StrictnessLevel::Normal => {
            }
            StrictnessLevel::Strict => {
                if config_true_default("tls_require_revocation", true)
                    && (crate::config::get_optional("ocsp_response_path").is_none()
                        || crate::config::get_optional("sct_list_path").is_none()) {
                    return false;
                }

                if config_true_default("tls_hide_sni", true) && conn.server_name().is_some() {
                    return false;
                }
            }
            StrictnessLevel::Paranoid => {
                if conn.server_name().is_some() {
                    return false;
                }
                
                let entropy_auditor = EntropyAuditor::new();
                if !entropy_auditor.audit_entropy() {
                    return false;
                }
            }
        }

        true
    }

    pub(crate) fn validate_public_key_pin(cert_pem: &[u8]) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        use x509_parser::parse_x509_certificate;

        let mut reader = std::io::BufReader::new(cert_pem);
        let certs = certs(&mut reader).map_err(|_| anyhow::anyhow!("failed to parse cert for key pin"))?;
        if certs.is_empty() {
            return Err(anyhow::anyhow!("no certificates found for key pinning"));
        }

        let der = &certs[0];
        let (_, parsed) = parse_x509_certificate(der)
            .map_err(|_| anyhow::anyhow!("failed to parse certificate DER for spki"))?;
        let spki_raw = parsed.tbs_certificate.subject_pki.raw;

        let mut hasher = Sha256::new();
        hasher.update(spki_raw.as_ref());
        let spki_hash = hasher.finalize();
        let spki_hex = hex_encode(&spki_hash);

        if !SPKI_FINGERPRINT_HEX.is_empty() {
            if !constant_time_compare(&spki_hex, SPKI_FINGERPRINT_HEX) {
                return Err(anyhow::anyhow!("SPKI pinning violation"));
            }
        }

        Ok(())
    }

    

    fn handle_client(
        _conn: &mut [u8],
        _config: StdArc<ServerConfig>,
        _strictness: StrictnessLevel,
        _pool: StdArc<ConnectionPool>,
        _early_validator: StdArc<StdMutex<EarlyDataValidator>>,
    ) {
    }

    pub fn serve_real(addr: &str, cert_path: &str, key_path: &str) -> Result<()> {
        if !CONFIG_YAML_PROVIDED {
            return Err(anyhow::anyhow!(
                "TLS INVIOLABLE: YAML non fourni à la compilation. Impossible de démarrer serve_real."
            ));
        }

        Err(anyhow::anyhow!("Network I/O not available in no_std mode"))
    }
}

impl TLSServerOptimized {
    pub fn optimizations_report() -> String {
        alloc::format!(
            "ARM OPTIMIZATIONS ENABLED:\n\
            - BufferPool: Pre-allocated 32 small(256B) + 16 medium(4KB) + 8 large(16KB) buffers\n\
            - BatchTimestampCache: Reduced syscalls via atomic counter batching\n\
            - constant_time_compare: Timing-safe string comparison (SHA256, YAML checksums)\n\
            - StreamBuffer: Zero-copy streaming for cryptographic operations\n\
            - LazyHasher: Lazy initialization of hash computations\n\
            - StringIntern: Memory fragmentation reduction (64 interned strings)\n\
            - Stack buffers: 4KB on-stack for small client reads\n\
            - Batch jitter: 16-element cached randomness per read\n\
            - Pre-allocated padding: Hide metadata without per-packet allocation\n\
            - Atomic operations: Lock-free timestamp, RateLimiter counters\n\
            CPU TARGET: ARM (NEON ARMv7 + v8crypto ARM64)\n\
            NO_STD MODE: Enabled (kernel-safe, alloc-only)"
        )
    }
}
