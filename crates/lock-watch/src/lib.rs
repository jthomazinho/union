//! Detect when the local user's screen gets locked.
//!
//! Each OS gets the most reliable poll-based primitive available without
//! pulling in heavy dependencies:
//!  - **Linux**: `loginctl show-session self -p LockedHint --value` (systemd >= 240).
//!  - **macOS**: `CGSessionCopyCurrentDictionary` + `CGSSessionScreenIsLocked`.
//!  - **Windows**: `OpenInputDesktop(DESKTOP_SWITCHDESKTOP)` — fails with
//!    `ACCESS_DENIED` when the secure desktop (lock screen) is active.
//!
//! The watcher polls every 2s and fires a callback when the state changes;
//! the initial state is reported once at startup if it's `Locked`.

use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Locked,
    Unlocked,
}

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Run a background thread that calls `on_change` whenever the lock state
/// flips. The thread runs for the lifetime of the process.
pub fn spawn<F>(mut on_change: F) -> std::io::Result<thread::JoinHandle<()>>
where
    F: FnMut(LockState) + Send + 'static,
{
    thread::Builder::new()
        .name("lock-watch".into())
        .spawn(move || {
            let mut last: Option<bool> = None;
            loop {
                if let Some(locked) = poll_is_locked() {
                    if last != Some(locked) {
                        on_change(if locked {
                            LockState::Locked
                        } else {
                            LockState::Unlocked
                        });
                        last = Some(locked);
                    }
                }
                thread::sleep(POLL_INTERVAL);
            }
        })
}

/// `None` means the OS query failed (and we shouldn't act on it).
fn poll_is_locked() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        linux::is_locked()
    }
    #[cfg(target_os = "macos")]
    {
        macos::is_locked()
    }
    #[cfg(target_os = "windows")]
    {
        windows::is_locked()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;
    pub fn is_locked() -> Option<bool> {
        let out = Command::new("loginctl")
            .args(["show-session", "self", "-p", "LockedHint", "--value"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = std::str::from_utf8(&out.stdout).ok()?.trim();
        Some(s == "yes")
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;

    type CFTypeRef = *const c_void;
    type CFDictionaryRef = CFTypeRef;
    type CFStringRef = CFTypeRef;
    type CFBooleanRef = CFTypeRef;

    // kCFStringEncodingASCII = 0x0600
    const ASCII_ENCODING: u32 = 0x0600;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFDictionaryGetValue(d: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
        fn CFStringCreateWithCString(
            alloc: CFTypeRef,
            c_str: *const u8,
            encoding: u32,
        ) -> CFStringRef;
        fn CFBooleanGetValue(b: CFBooleanRef) -> u8;
        fn CFRelease(cf: CFTypeRef);
    }

    pub fn is_locked() -> Option<bool> {
        unsafe {
            let dict = CGSessionCopyCurrentDictionary();
            if dict.is_null() {
                return None;
            }
            let key = CFStringCreateWithCString(
                std::ptr::null(),
                c"CGSSessionScreenIsLocked".as_ptr() as *const u8,
                ASCII_ENCODING,
            );
            if key.is_null() {
                CFRelease(dict);
                return None;
            }
            let val = CFDictionaryGetValue(dict, key);
            // Read the bool *before* releasing the dictionary that owns `val`.
            let locked = if val.is_null() {
                false
            } else {
                CFBooleanGetValue(val) != 0
            };
            CFRelease(key);
            CFRelease(dict);
            Some(locked)
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, DESKTOP_SWITCHDESKTOP,
    };

    pub fn is_locked() -> Option<bool> {
        unsafe {
            let desk = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
            if desk.is_null() {
                // Could not access the input desktop — secure (lock) desktop
                // is active. This is the canonical signal used by sysinternals
                // / NirSoft tools.
                return Some(true);
            }
            CloseDesktop(desk);
            Some(false)
        }
    }
}
