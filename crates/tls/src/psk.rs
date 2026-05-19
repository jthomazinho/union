//! PSK derivation and HMAC challenge/response.
//!
//! The user configures a passphrase; both sides derive a 32-byte PSK via
//! SHA-256("union-psk-v1:" || passphrase). For each new connection the
//! server picks a random nonce, the client replies with HMAC-SHA256(psk, nonce),
//! and the server compares constant-time. Cheap, simple, replay-safe per nonce.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const PSK_LABEL: &[u8] = b"union-psk-v1:";

pub fn derive_psk_from_passphrase(passphrase: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(PSK_LABEL);
    h.update(passphrase.as_bytes());
    h.finalize().into()
}

pub fn hmac_psk(psk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(psk).expect("32-byte key always valid");
    mac.update(nonce);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Constant-time comparison.
pub fn verify_psk(psk: &[u8; 32], nonce: &[u8; 32], expected: &[u8; 32]) -> bool {
    let mut mac = HmacSha256::new_from_slice(psk).expect("32-byte key always valid");
    mac.update(nonce);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_roundtrip() {
        let psk = derive_psk_from_passphrase("correct-horse-battery-staple");
        let nonce = [42u8; 32];
        let proof = hmac_psk(&psk, &nonce);
        assert!(verify_psk(&psk, &nonce, &proof));
    }

    #[test]
    fn wrong_psk_rejected() {
        let psk_a = derive_psk_from_passphrase("a");
        let psk_b = derive_psk_from_passphrase("b");
        let nonce = [9u8; 32];
        let proof = hmac_psk(&psk_a, &nonce);
        assert!(!verify_psk(&psk_b, &nonce, &proof));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let psk = derive_psk_from_passphrase("x");
        let proof = hmac_psk(&psk, &[1u8; 32]);
        assert!(!verify_psk(&psk, &[2u8; 32], &proof));
    }
}
