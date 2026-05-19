//! TLS + PSK authentication scaffolding. Implementation lives in the modules.
pub mod cert;
pub mod psk;
pub mod transport;

pub use cert::{fingerprint_sha256, generate_self_signed, CertPair};
pub use psk::{derive_psk_from_passphrase, hmac_psk, verify_psk};
pub use transport::{
    client_connect, client_connect_with_observer, server_acceptor, ObservedFingerprint,
};
