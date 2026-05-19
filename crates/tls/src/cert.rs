//! Self-signed cert generation and fingerprinting.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct CertPair {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a fresh self-signed ECDSA P-256 cert. Used by the server on first
/// run; the resulting PEMs are stored on disk and reused thereafter.
pub fn generate_self_signed(common_name: &str) -> anyhow::Result<CertPair> {
    let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok(CertPair {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// SHA-256 of the DER-encoded certificate (the bytes between
/// `-----BEGIN CERTIFICATE-----` markers). This is what the client pins.
pub fn fingerprint_sha256(cert_pem: &str) -> anyhow::Result<[u8; 32]> {
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor).collect::<Result<_, _>>()?;
    let first = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no certificates in PEM"))?;
    let mut h = Sha256::new();
    h.update(first.as_ref());
    Ok(h.finalize().into())
}

pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    hex::encode(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_fingerprints() {
        let pair = generate_self_signed("test.local").unwrap();
        assert!(pair.cert_pem.contains("BEGIN CERTIFICATE"));
        let fp1 = fingerprint_sha256(&pair.cert_pem).unwrap();
        let fp2 = fingerprint_sha256(&pair.cert_pem).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn distinct_certs_have_distinct_fingerprints() {
        let a = generate_self_signed("a.local").unwrap();
        let b = generate_self_signed("b.local").unwrap();
        let fa = fingerprint_sha256(&a.cert_pem).unwrap();
        let fb = fingerprint_sha256(&b.cert_pem).unwrap();
        assert_ne!(fa, fb);
    }
}
