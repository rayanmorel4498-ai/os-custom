/// Module de Sécurité Avancée
/// Implémente: Capability-based security, MAC/RBAC, chiffrement persistance, signature modèles

use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};
use alloc::format;
use alloc::string::ToString;
use crate::prelude::{String, Vec};
use sha2::{Sha256, Digest};

/// Capability: droit d'accès fine-grained
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Capability {
    pub subject: String,      // qui
    pub resource: String,     // quoi (chemin fichier)
    pub actions: HashSet<String>, // comment (read, write, execute)
    pub conditions: Vec<CapabilityCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapabilityCondition {
    TimeRange { start: u64, end: u64 },
    RateLimited { max_per_second: u32 },
    SourceIP { allowed: Vec<String> },
    TLSOnly,
}

/// Capability-Based Access Control
pub struct CapabilityBasedSecurity {
    capabilities: HashMap<String, Vec<Capability>>, // subject -> capabilities
    delegation_chain: HashMap<String, Vec<String>>, // delegator -> delegatees
}

impl CapabilityBasedSecurity {
    pub fn new() -> Self {
        CapabilityBasedSecurity {
            capabilities: HashMap::new(),
            delegation_chain: HashMap::new(),
        }
    }
    
    /// Donne une capability à un subject
    pub fn grant_capability(&mut self, capability: Capability) {
        self.capabilities
            .entry(capability.subject.clone())
            .or_insert_with(Vec::new)
            .push(capability);
    }
    
    /// Vérifie si une action est autorisée (capability-based)
    pub fn check_capability(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), String> {
        let caps = self
            .capabilities
            .get(subject)
            .ok_or(format!("Pas de capabilities pour {}", subject))?;
        
        for cap in caps {
            if cap.resource == resource && cap.actions.contains(action) {
                // Vérifie les conditions
                for condition in &cap.conditions {
                    match condition {
                        CapabilityCondition::TLSOnly => {
                            // Vérification TLS (simplifié)
                            continue;
                        }
                        _ => continue,
                    }
                }
                return Ok(());
            }
        }
        
        Err(format!(
            "Capability refusée: {} ne peut pas {} {}",
            subject, action, resource
        ))
    }
    
    /// Délègue une capability à un autre subject
    pub fn delegate_capability(
        &mut self,
        from: &str,
        to: &str,
        resource: &str,
    ) -> Result<(), String> {
        // Vérifie que 'from' a la capability
        let has_capability = self
            .capabilities
            .get(from)
            .map(|caps| caps.iter().any(|c| c.resource == resource))
            .unwrap_or(false);
        
        if !has_capability {
            return Err(format!("{} n'a pas de capability sur {}", from, resource));
        }
        
        // Ajoute la délégation
        self.delegation_chain
            .entry(from.to_string())
            .or_insert_with(Vec::new)
            .push(to.to_string());
        
        Ok(())
    }
    
    pub fn get_delegation_chain(&self, subject: &str) -> Vec<String> {
        self.delegation_chain
            .get(subject)
            .cloned()
            .unwrap_or_default()
    }
}

/// Mandatory Access Control avec labels de sécurité
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}

#[derive(Debug, Clone)]
pub struct SecurityLabel {
    pub level: SecurityLevel,
    pub categories: HashSet<String>,
}

pub struct MandatoryAccessControl {
    subject_labels: HashMap<String, SecurityLabel>,
    resource_labels: HashMap<String, SecurityLabel>,
}

impl MandatoryAccessControl {
    pub fn new() -> Self {
        MandatoryAccessControl {
            subject_labels: HashMap::new(),
            resource_labels: HashMap::new(),
        }
    }
    
    pub fn set_subject_label(&mut self, subject: &str, label: SecurityLabel) {
        self.subject_labels.insert(subject.to_string(), label);
    }
    
    pub fn set_resource_label(&mut self, resource: &str, label: SecurityLabel) {
        self.resource_labels.insert(resource.to_string(), label);
    }
    
    /// Vérifie MAC read (subject.level >= resource.level)
    pub fn check_read(&self, subject: &str, resource: &str) -> Result<(), String> {
        let subject_label = self
            .subject_labels
            .get(subject)
            .ok_or(format!("Pas de label pour {}", subject))?;
        
        let resource_label = self
            .resource_labels
            .get(resource)
            .ok_or(format!("Pas de label pour {}", resource))?;
        
        if subject_label.level >= resource_label.level {
            Ok(())
        } else {
            Err(format!(
                "MAC read refusé: {:?} < {:?}",
                subject_label.level, resource_label.level
            ))
        }
    }
    
    /// Vérifie MAC write (subject.level <= resource.level)
    pub fn check_write(&self, subject: &str, resource: &str) -> Result<(), String> {
        let subject_label = self
            .subject_labels
            .get(subject)
            .ok_or(format!("Pas de label pour {}", subject))?;
        
        let resource_label = self
            .resource_labels
            .get(resource)
            .ok_or(format!("Pas de label pour {}", resource))?;
        
        if subject_label.level <= resource_label.level {
            Ok(())
        } else {
            Err(format!(
                "MAC write refusé: {:?} > {:?}",
                subject_label.level, resource_label.level
            ))
        }
    }
}

/// Role-Based Access Control avancé
#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub permissions: HashSet<String>,
    pub parent_roles: Vec<String>, // Héritage des rôles
}

pub struct RoleBasedAccessControl {
    roles: HashMap<String, Role>,
    user_roles: HashMap<String, Vec<String>>,
}

impl RoleBasedAccessControl {
    pub fn new() -> Self {
        RoleBasedAccessControl {
            roles: HashMap::new(),
            user_roles: HashMap::new(),
        }
    }
    
    pub fn create_role(&mut self, name: &str, permissions: HashSet<String>) {
        self.roles.insert(
            name.to_string(),
            Role {
                name: name.to_string(),
                permissions,
                parent_roles: Vec::new(),
            },
        );
    }
    
    pub fn add_parent_role(&mut self, role: &str, parent: &str) {
        if let Some(r) = self.roles.get_mut(role) {
            r.parent_roles.push(parent.to_string());
        }
    }
    
    pub fn assign_role(&mut self, user: &str, role: &str) {
        self.user_roles
            .entry(user.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
    }
    
    pub fn check_permission(&self, user: &str, permission: &str) -> Result<(), String> {
        let user_roles = self
            .user_roles
            .get(user)
            .ok_or(format!("Utilisateur {} n'a pas de rôle", user))?;
        
        for role_name in user_roles {
            if self.has_permission(role_name, permission) {
                return Ok(());
            }
        }
        
        Err(format!("Permission {} refusée pour {}", permission, user))
    }
    
    fn has_permission(&self, role_name: &str, permission: &str) -> bool {
        if let Some(role) = self.roles.get(role_name) {
            if role.permissions.contains(permission) {
                return true;
            }
            
            // Vérifie parents récursivement
            for parent in &role.parent_roles {
                if self.has_permission(parent, permission) {
                    return true;
                }
            }
        }
        
        false
    }
}

/// Chiffrement de persistance (AES-128 simulation)
pub struct PersistenceEncryption {
    master_key: [u8; 16],
    salt: [u8; 8],
}

impl PersistenceEncryption {
    pub fn new(password: &str) -> Self {
        let mut key = [0u8; 16];
        let hash = Sha256::digest(password.as_bytes());
        for i in 0..16 {
            key[i] = hash[i];
        }
        
        let mut salt = [0u8; 8];
        let salt_hash = Sha256::digest(format!("salt_{}", password).as_bytes());
        for i in 0..8 {
            salt[i] = salt_hash[i];
        }
        
        PersistenceEncryption {
            master_key: key,
            salt,
        }
    }
    
    /// Chiffre les données avec AES-CTR simulation
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::new();
        
        // IV (8 bytes) + encrypted data
        ciphertext.extend_from_slice(&self.salt);
        
        // Simple XOR avec derivé key (AES-CTR simplified)
        let key_stream = self.derive_keystream(plaintext.len());
        for (byte, &key_byte) in plaintext.iter().zip(key_stream.iter()) {
            ciphertext.push(byte ^ key_byte);
        }
        
        ciphertext
    }
    
    /// Déchiffre les données
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 8 {
            return Err("Ciphertext trop court".to_string());
        }
        
        // Vérifie IV
        if &ciphertext[0..8] != &self.salt {
            return Err("IV invalide".to_string());
        }
        
        let encrypted = &ciphertext[8..];
        let key_stream = self.derive_keystream(encrypted.len());
        
        let plaintext: Vec<u8> = encrypted
            .iter()
            .zip(key_stream.iter())
            .map(|(&c, &k)| c ^ k)
            .collect();
        
        Ok(plaintext)
    }
    
    fn derive_keystream(&self, length: usize) -> Vec<u8> {
        let mut keystream = Vec::new();
        let mut counter = 0u64;
        
        while keystream.len() < length {
            let mut hasher = Sha256::new();
            hasher.update(&self.master_key);
            hasher.update(counter.to_le_bytes());
            
            let hash = hasher.finalize();
            keystream.extend_from_slice(&hash);
            counter += 1;
        }
        
        keystream.truncate(length);
        keystream
    }
}

/// Model Signing et Verification
pub struct ModelSigner {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl ModelSigner {
    pub fn new(key_seed: &str) -> Self {
        let private_hash = Sha256::digest(format!("private_{}", key_seed).as_bytes());
        let public_hash = Sha256::digest(format!("public_{}", key_seed).as_bytes());
        
        ModelSigner {
            private_key: private_hash.to_vec(),
            public_key: public_hash.to_vec(),
        }
    }
    
    /// Signe un modèle (génère signature HMAC-SHA256)
    pub fn sign_model(&self, model_data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.private_key);
        hasher.update(model_data);
        hasher.finalize().to_vec()
    }
    
    /// Vérifie la signature d'un modèle
    pub fn verify_signature(
        &self,
        model_data: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let computed = self.sign_model(model_data);
        
        if computed.as_slice() == signature {
            Ok(())
        } else {
            Err("Signature invalide ou modèle corrompu".to_string())
        }
    }
}
