//! Per-peer auth-failure throttle.
//!
//! Brute-forcing the PSK on a LAN is realistic if the passphrase is short.
//! We track failures by source IP; after [`MAX_FAILURES`] in a row, that IP
//! is blocked for an exponentially-growing window (capped at
//! [`BACKOFF_MAX`]). A success or a long quiet period resets the counter.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// How many failures in a row before the peer is held off.
const MAX_FAILURES: u32 = 3;
/// First block window. Doubles for each additional failure beyond the threshold.
const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Upper bound on the block window.
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// If the peer is quiet for this long, forget past failures.
const FAILURE_DECAY: Duration = Duration::from_secs(60);

#[derive(Default)]
struct PeerState {
    failures: u32,
    last_failure: Option<Instant>,
    blocked_until: Option<Instant>,
}

#[derive(Clone, Default)]
pub struct AuthThrottle(Arc<Mutex<HashMap<IpAddr, PeerState>>>);

impl AuthThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `Some(remaining)` if `ip` is currently blocked, else `None`.
    pub async fn blocked(&self, ip: IpAddr) -> Option<Duration> {
        let map = self.0.lock().await;
        let s = map.get(&ip)?;
        let until = s.blocked_until?;
        let now = Instant::now();
        if now < until {
            Some(until - now)
        } else {
            None
        }
    }

    /// Record an auth failure for `ip`. May transition the peer into the
    /// blocked state and bump its backoff.
    pub async fn record_failure(&self, ip: IpAddr) {
        crate::metrics::inc(&crate::metrics::AUTH_FAILURES, 1);
        let now = Instant::now();
        let mut map = self.0.lock().await;
        let entry = map.entry(ip).or_default();
        if let Some(last) = entry.last_failure {
            if now.duration_since(last) > FAILURE_DECAY {
                entry.failures = 0;
                entry.blocked_until = None;
            }
        }
        entry.failures += 1;
        entry.last_failure = Some(now);
        if entry.failures >= MAX_FAILURES {
            let extra = entry.failures - MAX_FAILURES;
            let backoff = BACKOFF_BASE
                .checked_mul(1u32.checked_shl(extra).unwrap_or(u32::MAX))
                .unwrap_or(BACKOFF_MAX)
                .min(BACKOFF_MAX);
            entry.blocked_until = Some(now + backoff);
        }
    }

    /// Forget any prior failures for `ip` (e.g. on a successful handshake).
    pub async fn record_success(&self, ip: IpAddr) {
        self.0.lock().await.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn blocks_after_threshold() {
        let t = AuthThrottle::new();
        let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
        for _ in 0..MAX_FAILURES {
            assert!(t.blocked(ip).await.is_none());
            t.record_failure(ip).await;
        }
        assert!(t.blocked(ip).await.is_some());
    }

    #[tokio::test]
    async fn success_clears_state() {
        let t = AuthThrottle::new();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        for _ in 0..MAX_FAILURES {
            t.record_failure(ip).await;
        }
        assert!(t.blocked(ip).await.is_some());
        t.record_success(ip).await;
        assert!(t.blocked(ip).await.is_none());
    }

    #[tokio::test]
    async fn backoff_grows() {
        let t = AuthThrottle::new();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        for _ in 0..MAX_FAILURES {
            t.record_failure(ip).await;
        }
        let first = t.blocked(ip).await.unwrap();
        t.record_failure(ip).await;
        let second = t.blocked(ip).await.unwrap();
        assert!(
            second > first,
            "expected backoff to grow: {first:?} -> {second:?}"
        );
    }
}
