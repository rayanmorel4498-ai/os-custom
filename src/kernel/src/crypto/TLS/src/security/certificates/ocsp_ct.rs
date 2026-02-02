extern crate alloc;

use anyhow::Result;
use alloc::vec::Vec;

#[cfg(feature = "real_tls")]
pub mod ocsp_ct {
    use super::*;
    use rustls::sign::CertifiedKey;

    pub fn load_ocsp_response(path: &str) -> Result<Vec<u8>> {
        let _ = path;
        Err(anyhow::anyhow!("File I/O not available in no_std mode"))
    }

    pub fn load_sct_list(path: &str) -> Result<Vec<u8>> {
        let _ = path;
        Err(anyhow::anyhow!("File I/O not available in no_std mode"))
    }

    pub fn add_ocsp_to_cert(mut cert: CertifiedKey, ocsp_response: Vec<u8>) -> CertifiedKey {
        cert.ocsp = Some(ocsp_response);
        cert
    }

    pub fn validate_ocsp_response(ocsp_bytes: &[u8]) -> Result<()> {
        if ocsp_bytes.is_empty() {
            return Err(anyhow::anyhow!("OCSP response is empty"));
        }
        Ok(())
    }

    pub fn validate_sct_list(sct_bytes: &[u8]) -> Result<()> {
        if sct_bytes.is_empty() {
            return Err(anyhow::anyhow!("SCT list is empty"));
        }
        Ok(())
    }

    pub fn load_and_validate_ocsp_ct(ocsp_path: &str, sct_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let ocsp = load_ocsp_response(ocsp_path)?;
        let sct = load_sct_list(sct_path)?;
        validate_ocsp_response(&ocsp)?;
        validate_sct_list(&sct)?;
        Ok((ocsp, sct))
    }
}

#[cfg(not(feature = "real_tls"))]
pub mod ocsp_ct {
    use super::*;

    pub fn load_ocsp_response(_path: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("OCSP not available without real_tls feature"))
    }

    pub fn load_sct_list(_path: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("SCT not available without real_tls feature"))
    }

    pub fn validate_ocsp_response(_ocsp_bytes: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!("OCSP validation not available without real_tls feature"))
    }

    pub fn validate_sct_list(_sct_bytes: &[u8]) -> Result<()> {
        Err(anyhow::anyhow!("SCT validation not available without real_tls feature"))
    }

    pub fn load_and_validate_ocsp_ct(_ocsp_path: &str, _sct_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(anyhow::anyhow!("OCSP/CT not available without real_tls feature"))
    }
}
