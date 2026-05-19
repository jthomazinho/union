//! On-disk persistence for the server's self-signed TLS cert.

use std::path::Path;

use union_tls::cert::{fingerprint_hex, fingerprint_sha256, generate_self_signed, CertPair};

const CERT_FILE: &str = "server.crt";
const KEY_FILE: &str = "server.key";

pub fn load_or_generate(dir: &Path, common_name: &str) -> anyhow::Result<(CertPair, [u8; 32])> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    let pair = if cert_path.exists() && key_path.exists() {
        CertPair {
            cert_pem: std::fs::read_to_string(&cert_path)?,
            key_pem: std::fs::read_to_string(&key_path)?,
        }
    } else {
        let pair = generate_self_signed(common_name)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&cert_path, &pair.cert_pem)?;
        // Restrict key permissions on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&key_path)?;
            std::io::Write::write_all(&mut f, pair.key_pem.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&key_path, &pair.key_pem)?;
        }
        tracing::info!("generated new TLS cert at {}", cert_path.display());
        pair
    };
    let fp = fingerprint_sha256(&pair.cert_pem)?;
    tracing::info!("server cert fingerprint: {}", fingerprint_hex(&fp));
    Ok((pair, fp))
}
