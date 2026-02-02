extern crate alloc;
use anyhow::{Result, anyhow};

pub mod limits {
    pub const MAX_HOSTNAME_LEN: usize = 253;
    pub const MIN_HOSTNAME_LEN: usize = 1;
    pub const MAX_TOKEN_LEN: usize = 1024;
    pub const MIN_TOKEN_LEN: usize = 32;
    pub const MAX_COMPONENT_NAME_LEN: usize = 128;
    pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;
    pub const MIN_BUFFER_SIZE: usize = 64;
    pub const MAX_MASTER_KEY_LEN: usize = 512;
    pub const MIN_MASTER_KEY_LEN: usize = 14;
}

pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() || hostname.len() > limits::MAX_HOSTNAME_LEN {
        return Err(anyhow!("Invalid hostname length"));
    }

    for c in hostname.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => {},
            _ => return Err(anyhow!("Invalid character in hostname")),
        }
    }

    if hostname.starts_with('-') || hostname.starts_with('.') 
        || hostname.ends_with('-') || hostname.ends_with('.') {
        return Err(anyhow!("Hostname cannot start/end with dash or dot"));
    }

    if hostname.contains("..") {
        return Err(anyhow!("Hostname contains consecutive dots"));
    }

    for label in hostname.split('.') {
        if label.is_empty() {
            return Err(anyhow!("Empty hostname label"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow!("Hostname label cannot start/end with dash"));
        }
        if label.len() > 63 {
            return Err(anyhow!("Hostname label too long"));
        }
    }

    Ok(())
}

pub fn validate_token_id(token_id: &str) -> Result<()> {
    if token_id.is_empty() || token_id.len() > limits::MAX_TOKEN_LEN {
        return Err(anyhow!("Invalid token ID length"));
    }

    for c in token_id.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | ':' | '_' | '-' => {},
            _ => return Err(anyhow!("Invalid character in token ID")),
        }
    }

    Ok(())
}

pub fn validate_token_value(token_value: &str) -> Result<()> {
    if token_value.is_empty() || token_value.len() > limits::MAX_TOKEN_LEN {
        return Err(anyhow!("Invalid token value length"));
    }

    for c in token_value.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '=' => {},
            _ => return Err(anyhow!("Invalid character in token value")),
        }
    }

    Ok(())
}

pub fn validate_master_key(key: &str) -> Result<()> {
    if key.len() < limits::MIN_MASTER_KEY_LEN || key.len() > limits::MAX_MASTER_KEY_LEN {
        return Err(anyhow!("Master key length out of range"));
    }

    let mut byte_set = [false; 256];
    for &b in key.as_bytes() {
        byte_set[b as usize] = true;
    }
    let unique_bytes = byte_set.iter().filter(|&&b| b).count();
    if unique_bytes < 2 {
        return Err(anyhow!("Master key has insufficient entropy"));
    }

    Ok(())
}

pub fn validate_buffer_size(size: usize) -> Result<()> {
    if size < limits::MIN_BUFFER_SIZE || size > limits::MAX_BUFFER_SIZE {
        return Err(anyhow!("Buffer size out of range"));
    }

    Ok(())
}

pub fn validate_data_entropy(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Err(anyhow!("Cannot validate empty data"));
    }

    if data.iter().all(|&b| b == 0) {
        return Err(anyhow!("Data has zero entropy"));
    }

    Ok(())
}

pub fn validate_ip_address(ip: &str) -> Result<()> {
    if ip.is_empty() || ip.len() > 45 {
        return Err(anyhow!("Invalid IP address length"));
    }

    let is_ipv4 = ip.chars().all(|c| c.is_ascii_digit() || c == '.');
    let is_ipv6 = ip.chars().all(|c| c.is_ascii_hexdigit() || c == ':');

    if !is_ipv4 && !is_ipv6 {
        return Err(anyhow!("Invalid IP address format"));
    }

    if is_ipv4 {
        let parts: alloc::vec::Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid IPv4 format"));
        }
        for part in parts {
            if part.is_empty() {
                return Err(anyhow!("Invalid IPv4 octet"));
            }
        }
    }

    Ok(())
}

pub fn validate_component_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > limits::MAX_COMPONENT_NAME_LEN {
        return Err(anyhow!("Invalid component name length"));
    }

    for c in name.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => {},
            _ => return Err(anyhow!("Invalid character in component name")),
        }
    }

    Ok(())
}

pub fn validate_signature(sig: &str) -> Result<()> {
    if sig.is_empty() || sig.len() > limits::MAX_TOKEN_LEN {
        return Err(anyhow!("Invalid signature length"));
    }

    for c in sig.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '+' | '/' | '-' | '_' | '=' => {},
            _ => return Err(anyhow!("Invalid character in signature")),
        }
    }

    Ok(())
}

pub fn validate_context(context: &str) -> Result<()> {
    if context.is_empty() || context.len() > 256 {
        return Err(anyhow!("Invalid context length"));
    }

    for c in context.chars() {
        if !c.is_ascii_graphic() && c != ' ' {
            return Err(anyhow!("Invalid character in context"));
        }
    }

    Ok(())
}

pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 {
        return Err(anyhow!("Invalid path length"));
    }

    if path.contains("..") || path.contains("//") {
        return Err(anyhow!("Path traversal attempt detected"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_invalid() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid").is_err());
    }

    #[test]
    fn test_validate_token_id() {
        assert!(validate_token_id("token_123").is_ok());
        assert!(validate_token_id("").is_err());
    }

    #[test]
    fn test_validate_master_key() {
        assert!(validate_master_key("test_key_1234567").is_ok());
        assert!(validate_master_key("short").is_err());
    }

    #[test]
    fn test_validate_buffer_size() {
        assert!(validate_buffer_size(1024).is_ok());
        assert!(validate_buffer_size(10).is_err());
    }

    #[test]
    fn test_validate_data_entropy() {
        assert!(validate_data_entropy(&[1, 2, 3]).is_ok());
        assert!(validate_data_entropy(&[0, 0, 0]).is_err());
    }

    #[test]
    fn test_validate_component_name() {
        assert!(validate_component_name("CPU").is_ok());
        assert!(validate_component_name("invalid-name").is_err());
    }
}
