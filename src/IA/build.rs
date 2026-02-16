use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let bootstrap_hex = bootstrap_key_hex();
    let ia_id_hex = require_hex_env("REDMI_IA_ID", 16);
    let key_bytes = bootstrap_hex.as_bytes();
    let nonce = build_nonce();
    let nonce_hex = format!("{:032x}", nonce);
    let request_base = format!(
        "IA_BOOT_REQ;v=1;op=BOOT;mode=run;first_run=1;ia_id={};nonce={}",
        ia_id_hex,
        nonce_hex
    );
    let sig_hex = sign_with_key(key_bytes, &request_base);
    let request = format!("{};sig={}", request_base, sig_hex);

    let control_socket = control_socket_path();
    let mut stream = UnixStream::connect(&control_socket)
        .unwrap_or_else(|_| panic!("unable to connect to {}", control_socket));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    stream.write_all(request.as_bytes()).expect("write boot request");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("read boot response");
    if buf.is_empty() {
        panic!("empty IA_BOOT_OK response");
    }
    let response = String::from_utf8(buf).expect("boot response utf8");
    let (ia_id_hex, secret_hex, handle, resp_sig, enc_hex) = parse_boot_ok(&response, &nonce_hex);

    let base = format!("IA_BOOT_OK;v=1;handle={};enc={}", handle, enc_hex);
    let expected_sig = sign_with_key(key_bytes, &base);
    if resp_sig != expected_sig {
        panic!("IA_BOOT_OK signature invalid");
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_path = manifest_dir.join("src/config/generated_build.rs");
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create generated config dir");
    }
    let content = format!(
        "// @generated\n\
         pub const IA_ID_HEX: &str = \"{}\";\n\
         pub const IA_SECRET_HEX: &str = \"{}\";\n",
        ia_id_hex,
        secret_hex
    );
    fs::write(&out_path, content).expect("write generated_build.rs");
}

fn build_nonce() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let nanos = now.as_nanos() as u64;
    let pid = std::process::id() as u64;
    nanos ^ (pid.rotate_left(13)) ^ 0x9e3779b97f4a7c15u64
}

fn parse_boot_ok(text: &str, nonce_hex: &str) -> (String, String, String, String, String) {
    let mut ia_id = String::new();
    let mut secret = String::new();
    let mut sig = String::new();
    let mut enc = String::new();
    let mut handle = String::new();
    let mut version = 0u32;
    for part in text.split(';') {
        if part.is_empty() {
            continue;
        }
        let mut kv = part.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");
        match key {
            "IA_BOOT_OK" => {}
            "v" => version = value.parse::<u32>().unwrap_or(0),
            "handle" => handle = value.to_string(),
            "enc" => enc = value.to_string(),
            "sig" => sig = value.to_string(),
            _ => {}
        }
    }
    if version != 1 || handle.is_empty() || enc.is_empty() || sig.is_empty() {
        panic!("invalid IA_BOOT_OK response");
    }

    let payload = decrypt_with_bootstrap(&bootstrap_key_hex(), nonce_hex, &enc)
        .unwrap_or_else(|_| panic!("IA_BOOT_OK decrypt failed"));
    for part in payload.split(';') {
        if let Some(v) = part.strip_prefix("ia_id=") {
            ia_id = v.to_string();
        } else if let Some(v) = part.strip_prefix("ia_key=") {
            secret = v.to_string();
        }
    }
    if ia_id.is_empty() || secret.is_empty() {
        panic!("invalid IA_BOOT_OK payload");
    }

    (ia_id, secret, handle, sig, enc)
}

fn sign_with_key(key: &[u8], base: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(base.as_bytes());
    hex_encode(&hasher.finalize())
}

fn bootstrap_key_hex() -> String {
    let key = env::var("REDMI_BOOTSTRAP_KEY")
        .or_else(|_| env::var("REDMI_BOOT_SECRET"))
        .unwrap_or_default();
    if !key.is_empty() {
        return key;
    }
    if let Some(key) = read_bootstrap_from_yaml() {
        return key;
    }
    panic!("missing_bootstrap_key");
}

fn control_socket_path() -> String {
    env::var("REDMI_TLS_CONTROL_SOCK").unwrap_or_else(|_| panic!("REDMI_TLS_CONTROL_SOCK manquant"))
}

fn read_bootstrap_from_yaml() -> Option<String> {
    let manifest = env::var("CARGO_MANIFEST_DIR").ok()?;
    let mut bases = Vec::new();
    bases.push(manifest);
    bases.push(String::from(".."));
    bases.push(String::from("../.."));
    bases.push(String::from("../../.."));
    bases.push(String::from("../../../.."));

    for base in bases {
        let paths = [
            format!("{}/secure.yaml", base),
            format!("{}/configs/secure.yaml", base),
            format!("{}/configs/certs/secure.yaml", base),
        ];
        for path in paths {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Some(key) = parse_bootstrap_from_yaml(&content) {
                    return Some(key);
                }
            }
        }
    }
    None
}

fn parse_bootstrap_from_yaml(content: &str) -> Option<String> {
    let mut in_security = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("security:") {
            in_security = true;
            continue;
        }
        if !trimmed.starts_with("-") && !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
            in_security = false;
        }
        if !in_security {
            continue;
        }
        let value = if let Some(rest) = trimmed.strip_prefix("bootstrap_key:") {
            rest
        } else if let Some(rest) = trimmed.strip_prefix("boot_secret:") {
            rest
        } else {
            continue;
        };
        let val = value.trim().trim_matches('"');
        if !val.is_empty() {
            return Some(val.to_ascii_lowercase());
        }
    }
    None
}

fn require_hex_env(name: &str, bytes_len: usize) -> String {
    let value = env::var(name).unwrap_or_default();
    if value.is_empty() {
        panic!("missing_env");
    }
    let expected = bytes_len * 2;
    let is_hex = value
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'));
    if value.len() != expected || !is_hex {
        panic!("invalid_hex_env");
    }
    value.to_ascii_lowercase()
}

fn decrypt_with_bootstrap(bootstrap_hex: &str, nonce_hex: &str, enc_hex: &str) -> Result<String, ()> {
    let key = hex_decode(bootstrap_hex).ok_or(())?;
    let nonce = hex_decode(nonce_hex).ok_or(())?;
    let cipher = hex_decode(enc_hex).ok_or(())?;
    let mut out = vec![0u8; cipher.len()];
    let mut counter: u32 = 0;
    let mut offset = 0;
    while offset < cipher.len() {
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(&nonce);
        hasher.update(&counter.to_le_bytes());
        let digest = hasher.finalize();
        let take = std::cmp::min(digest.len(), cipher.len() - offset);
        for i in 0..take {
            out[offset + i] = cipher[offset + i] ^ digest[i];
        }
        offset += take;
        counter = counter.wrapping_add(1);
    }
    String::from_utf8(out).map_err(|_| ())
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize]);
        out.push(LUT[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}
