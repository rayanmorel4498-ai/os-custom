extern crate alloc;

#[cfg(feature = "hsm")]
pub mod pkcs11 {
    use anyhow::Result;
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::object::{Attribute, AttributeType};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::session::{Session, SessionFlags, UserType};
    use cryptoki::types::Ulong;

    pub struct Pkcs11Signer {
        pkcs11: Pkcs11,
        slot: Ulong,
        pin: Option<String>,
    }

    impl Pkcs11Signer {
        pub fn new(module_path: &str, slot: Ulong, pin: Option<String>) -> Result<Self> {
            let pkcs11 = Pkcs11::new(module_path)?;
            let init_args = CInitializeArgs::new();
            let _ = pkcs11.initialize(init_args).ok();
            Ok(Self { pkcs11, slot, pin })
        }

        pub fn sign_with_label(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
            let session = self.pkcs11.open_session(self.slot, SessionFlags::new().set_serial_session(true), None, None)?;
            if let Some(ref p) = self.pin {
                session.login(UserType::User, Some(p))?;
            }

            let attrs = vec![
                Attribute::new_string(AttributeType::Label, label),
            ];
            let objs = session.find_objects(&attrs)?;
            if objs.is_empty() {
                return Err(anyhow::anyhow!("no object with label {}", label));
            }
            let key = objs[0];

            let mech = Mechanism::Ecdsa;
            session.sign_init(&mech, key)?;
            let sig = session.sign(data)?;

            if self.pin.is_some() {
                let _ = session.logout();
            }
            session.close()?;
            Ok(sig)
        }

        pub fn get_cert_by_label(&self, label: &str) -> Result<Vec<u8>> {
            use cryptoki::object::AttributeType;
            let session = self.pkcs11.open_session(self.slot, SessionFlags::new().set_serial_session(true), None, None)?;
            if let Some(ref p) = self.pin {
                session.login(UserType::User, Some(p))?;
            }

            let attrs = vec![
                Attribute::new_string(AttributeType::Label, label),
            ];
            let objs = session.find_objects(&attrs)?;
            if objs.is_empty() {
                return Err(anyhow::anyhow!("no object with label {}", label));
            }
            let obj = objs[0];

            let vals = session.get_attributes(obj, &[AttributeType::Value])?;
            session.close()?;
            if vals.is_empty() {
                return Err(anyhow::anyhow!("no CKA_VALUE for object {}", label));
            }
            if let Some(cryptoki::object::Attribute::Value(v)) = vals.into_iter().next() {
                Ok(v)
            } else {
                Err(anyhow::anyhow!("unexpected attribute type for CKA_VALUE"))
            }
        }
    }
}

#[cfg(not(feature = "hsm"))]
pub mod pkcs11 {
    use anyhow::Result;
    use alloc::string::String;
    use alloc::vec::Vec;

    pub struct Pkcs11Signer;

    impl Pkcs11Signer {
        pub fn new(_module_path: &str, _slot: u64, _pin: Option<String>) -> Result<Self> {
            Err(anyhow::anyhow!("cryptoki feature not enabled"))
        }
        pub fn sign_with_label(&self, _label: &str, _data: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow::anyhow!("cryptoki feature not enabled"))
        }
    }
}
