extern crate alloc;



#[cfg(feature = "real_tls")]
#[cfg_attr(feature = "real_tls", allow(dead_code))]
pub mod hsm_signer {
    use super::*;
    use anyhow::Result;
    
    #[cfg(feature = "hsm")]
    use crate::hsm::pkcs11::Pkcs11Signer;
    
    #[cfg(feature = "real_tls")]
    use rustls::sign::{SigningKey, Signer};
    #[cfg(feature = "real_tls")]
    use rustls::{SignatureScheme, SignatureAlgorithm};

    #[cfg(feature = "hsm")]
    pub struct HsmSigningKey {
        signer: alloc::sync::Arc<Pkcs11Signer>,
        label: alloc::string::String,
        scheme: SignatureScheme,
    }

    #[cfg(feature = "hsm")]
    struct HsmSigner {
        signer: alloc::sync::Arc<Pkcs11Signer>,
        label: alloc::string::String,
        scheme: SignatureScheme,
    }

    #[cfg(feature = "hsm")]
    impl Signer for HsmSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            let sig_bytes = self.signer
                .sign_with_label(&self.label, message)
                .map_err(|e| {
                    rustls::Error::General(alloc::format!("HSM sign failed: {}", e))
                })?;
            Ok(sig_bytes)
        }

        fn scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }

    #[cfg(feature = "hsm")]
    fn scheme_to_alg(scheme: SignatureScheme) -> SignatureAlgorithm {
        use SignatureScheme::*;
        match scheme {
            RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PKCS1_SHA512 | RSA_PSS_SHA256 | RSA_PSS_SHA384 | RSA_PSS_SHA512 => {
                SignatureAlgorithm::RSA
            }
            _ => SignatureAlgorithm::ECDSA,
        }
    }

    #[cfg(feature = "hsm")]
    impl HsmSigningKey {
        pub fn new(
            module_path: &str,
            slot: u64,
            pin: Option<alloc::string::String>,
            key_label: &str,
            scheme: SignatureScheme,
        ) -> Result<Self> {
            let signer = alloc::sync::Arc::new(Pkcs11Signer::new(module_path, slot, pin)?);
            Ok(Self {
                signer,
                label: key_label.to_string(),
                scheme,
            })
        }
    }

    #[cfg(feature = "hsm")]
    impl SigningKey for HsmSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            if offered.contains(&self.scheme) {
                Some(Box::new(HsmSigner {
                    signer: alloc::sync::Arc::clone(&self.signer),
                    label: self.label.clone(),
                    scheme: self.scheme,
                }))
            } else {
                None
            }
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            scheme_to_alg(self.scheme)
        }
    }

    #[cfg(not(feature = "hsm"))]
    pub struct HsmSigningKey;

    #[cfg(not(feature = "hsm"))]
    impl HsmSigningKey {
        pub fn new(
            _module_path: &str,
            _slot: u64,
            _pin: Option<alloc::string::String>,
            _key_label: &str,
            _scheme: SignatureScheme,
        ) -> Result<Self> {
            Err(anyhow::anyhow!("HSM signer not available; feature hsm not enabled"))
        }
    }

    #[cfg(not(feature = "hsm"))]
    impl SigningKey for HsmSigningKey {
        fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            None
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ECDSA
        }
    }
}

#[cfg(not(feature = "real_tls"))]
pub mod hsm_signer {
    pub struct HsmSigningKey;
    impl HsmSigningKey {
        pub fn new(
            _module_path: &str,
            _slot: u64,
            _pin: Option<alloc::string::String>,
            _key_label: &str,
            _scheme: (),
        ) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!("HSM signer not available without real_tls feature"))
        }
    }
}
