//! Lightweight in-process counters. Incremented from anywhere via atomic
//! ops, read once a second by the status-snapshot writer.

use std::sync::atomic::{AtomicU64, Ordering};

pub static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static FOCUS_SWITCHES: AtomicU64 = AtomicU64::new(0);
pub static SESSIONS_OPENED: AtomicU64 = AtomicU64::new(0);
pub static CLIPBOARD_TEXT_BYTES: AtomicU64 = AtomicU64::new(0);
pub static CLIPBOARD_IMAGE_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn inc(c: &AtomicU64, by: u64) {
    c.fetch_add(by, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Snapshot {
    pub auth_failures: u64,
    pub focus_switches: u64,
    pub sessions_opened: u64,
    pub clipboard_text_bytes: u64,
    pub clipboard_image_bytes: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        auth_failures: AUTH_FAILURES.load(Ordering::Relaxed),
        focus_switches: FOCUS_SWITCHES.load(Ordering::Relaxed),
        sessions_opened: SESSIONS_OPENED.load(Ordering::Relaxed),
        clipboard_text_bytes: CLIPBOARD_TEXT_BYTES.load(Ordering::Relaxed),
        clipboard_image_bytes: CLIPBOARD_IMAGE_BYTES.load(Ordering::Relaxed),
    }
}
