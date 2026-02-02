use std::env;
use std::fs;
use std::path::PathBuf;

fn parse_yaml_value(value_str: &str) -> String {
    // Remove comments (anything after #)
    let without_comment = if let Some(pos) = value_str.find('#') {
        &value_str[..pos]
    } else {
        value_str
    };
    
    // Trim whitespace and quotes
    without_comment.trim().trim_matches('"').to_string()
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir).join("config.rs");

    // Search for secure.yaml in multiple locations
    let yaml_paths = [
        "secure.yaml",
        "./secure.yaml",
        "../../../secure.yaml",
        "../../../../secure.yaml",
        "/home/rayan/Projets/Téléphone/secure.yaml",
    ];

    let mut found_yaml_path: Option<String> = None;
    let mut security_level = "5".to_string();
    let mut encryption_method = "AES-256-CTR".to_string();
    let mut master_key = String::new();
    let mut boot_token = String::new();

    // Find and parse secure.yaml
    for path in &yaml_paths {
        if fs::metadata(path).is_ok() {
            found_yaml_path = Some(path.to_string());
            
            if let Ok(content) = fs::read_to_string(path) {
                eprintln!("✓ kernel/build.rs: Found secure.yaml at: {}", path);
                
                let mut in_security_section = false;
                
                // Parse YAML to extract security configuration
                for line in content.lines() {
                    let trimmed = line.trim();
                    
                    // Skip empty lines and comments
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    
                    // Check if we're entering security section
                    if trimmed.starts_with("security:") {
                        in_security_section = true;
                        continue;
                    }
                    
                    // Check if we're leaving security section (new top-level key)
                    if !trimmed.starts_with("  ") && !trimmed.starts_with("\t") && trimmed.contains(':') {
                        in_security_section = false;
                    }
                    
                    // Parse only if we're in security section
                    if in_security_section {
                        // Parse security level
                        if trimmed.starts_with("level:") {
                            if let Some(val) = trimmed.strip_prefix("level:") {
                                security_level = parse_yaml_value(val);
                                eprintln!("  → Found security level: {}", security_level);
                            }
                        }
                        
                        // Parse encryption method
                        if trimmed.starts_with("encryption:") {
                            if let Some(val) = trimmed.strip_prefix("encryption:") {
                                encryption_method = parse_yaml_value(val);
                                eprintln!("  → Found encryption: {}", encryption_method);
                            }
                        }
                        
                        // Parse master key
                        if trimmed.starts_with("master_key:") {
                            if let Some(val) = trimmed.strip_prefix("master_key:") {
                                master_key = parse_yaml_value(val);
                                eprintln!("  → Found master_key ({} chars)", master_key.len());
                            }
                        }
                        
                        // Parse boot token
                        if trimmed.starts_with("boot_token:") {
                            if let Some(val) = trimmed.strip_prefix("boot_token:") {
                                boot_token = parse_yaml_value(val);
                                eprintln!("  → Found boot_token ({} chars)", boot_token.len());
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    if found_yaml_path.is_none() {
        eprintln!("⚠ kernel/build.rs: Warning - secure.yaml not found in any expected location");
        eprintln!("⚠ kernel/build.rs: Using default security configuration");
    } else if let Some(path) = &found_yaml_path {
        println!("cargo:rerun-if-changed={}", path);
    }

    // Do NOT embed high-entropy secrets into build artifacts. If `master_key` or `boot_token`
    // are not provided or look like placeholders (all zeros), we clear them here to avoid
    // accidental inclusion in the produced `config.rs`.
    let cleaned_master = if master_key.is_empty() || master_key.chars().all(|c| c == '0') {
        String::new()
    } else {
        // Warn the builder that a non-empty master key exists; prefer runtime provisioning.
        eprintln!("⚠ kernel/build.rs: master_key present in YAML — it's recommended to provide this at runtime instead of embedding it in build artifacts");
        String::from(master_key.clone())
    };

    let cleaned_boot = if boot_token.is_empty() || boot_token.chars().all(|c| c == '0') {
        String::new()
    } else {
        eprintln!("⚠ kernel/build.rs: boot_token present in YAML — prefer secure provisioning at runtime");
        String::from(boot_token.clone())
    };

    // Generate config.rs with extracted values (secrets may be empty)
    let config_code = format!(
        "pub const SECURITY_LEVEL: &str = \"{}\";\n\
         pub const ENCRYPTION_METHOD: &str = \"{}\";\n\
         pub const MASTER_KEY: &str = \"{}\";\n\
         pub const BOOT_TOKEN: &str = \"{}\";\n\
         pub const CONFIG_YAML_PROVIDED: bool = {};\n",
        security_level,
        encryption_method,
        cleaned_master,
        cleaned_boot,
        found_yaml_path.is_some()
    );

    fs::write(&out_path, config_code).expect("Failed to write config.rs");
    eprintln!("✓ kernel/build.rs: Generated config.rs");
    eprintln!("  ✓ Security Level: {}", security_level);
    eprintln!("  ✓ Encryption: {}", encryption_method);
    eprintln!("  ✓ Master Key: {} chars", cleaned_master.len());
    eprintln!("  ✓ Boot Token: {} chars", cleaned_boot.len());
}

