//! TLS + PSK authentication scaffolding. Implementation lives in the modules.
pub mod cert;
pub mod psk;
pub mod transport;

pub use cert::{generate_self_signed, fingerprint_sha256, CertPair};
pub use psk::{hmac_psk, verify_psk, derive_psk_from_passphrase};
pub use transport::{client_connect, server_acceptor};
