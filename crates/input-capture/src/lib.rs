//! Global input capture.
//!
//! Uses `rdev::grab` which gives us a callback per OS-level event with the
//! ability to consume (pass-through vs swallow). On macOS this is backed by
//! `CGEventTap`; on Linux/X11 by `XGrabPointer`/`XGrabKeyboard` via the
//! libinput shim; on Windows by `SetWindowsHookEx` with the **caveat** that
//! Windows low-level hooks cannot truly consume events from elevated
//! processes — that's a documented MVP limitation.
//!
//! When `enable()` is called, the callback swallows events and forwards them
//! over the channel. When disabled, the callback passes events through and
//! emits nothing.

mod keymap;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use protocol::{KeyCode, Modifiers, MouseButton};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub enum CaptureEvent {
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: MouseButton, pressed: bool },
    MouseWheel { dx: i16, dy: i16 },
    Key { key: KeyCode, pressed: bool, modifiers: Modifiers },
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("init: {0}")]
    Init(String),
    #[error("permission denied — accessibility/uinput access required")]
    PermissionDenied,
}

pub struct InputCapturer {
    active: Arc<AtomicBool>,
}

impl InputCapturer {
    pub fn enable(&self) {
        self.active.store(true, Ordering::Release);
    }
    pub fn disable(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub fn is_enabled(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

pub struct CaptureHandle {
    pub events: mpsc::UnboundedReceiver<CaptureEvent>,
    pub capturer: InputCapturer,
}

/// Spawn the OS-native capture thread. Returns a handle with an event
/// receiver and a control object. The thread runs for the lifetime of the
/// process — there's no clean shutdown because `rdev::grab` blocks forever.
pub fn start_capture() -> Result<CaptureHandle, CaptureError> {
    let (tx, rx) = mpsc::unbounded_channel();
    let active = Arc::new(AtomicBool::new(false));
    let active_thread = active.clone();

    std::thread::Builder::new()
        .name("input-capture".into())
        .spawn(move || run_grab_loop(active_thread, tx))
        .map_err(|e| CaptureError::Init(e.to_string()))?;

    Ok(CaptureHandle {
        events: rx,
        capturer: InputCapturer { active },
    })
}

fn run_grab_loop(active: Arc<AtomicBool>, tx: mpsc::UnboundedSender<CaptureEvent>) {
    // rdev::grab requires `Fn`, so all per-event state lives behind a
    // mutex. The lock is uncontended (single grab thread) — its only role
    // is to satisfy the type system.
    struct State {
        last_pos: Option<(f64, f64)>,
        mods: Modifiers,
    }
    let state = Arc::new(Mutex::new(State {
        last_pos: None,
        mods: Modifiers::default(),
    }));

    let cb = move |event: rdev::Event| -> Option<rdev::Event> {
        let passthrough_event = event.clone();
        let active_now = active.load(Ordering::Acquire);
        let mut st = state.lock().expect("capture state poisoned");

        match event.event_type {
            rdev::EventType::MouseMove { x, y } => {
                if let Some((lx, ly)) = st.last_pos {
                    let dx = (x - lx) as i32;
                    let dy = (y - ly) as i32;
                    if active_now && (dx != 0 || dy != 0) {
                        let _ = tx.send(CaptureEvent::MouseMove { dx, dy });
                    }
                }
                st.last_pos = Some((x, y));
            }
            rdev::EventType::ButtonPress(b) | rdev::EventType::ButtonRelease(b) => {
                let pressed = matches!(event.event_type, rdev::EventType::ButtonPress(_));
                if let Some(button) = keymap::rdev_button_to_proto(b) {
                    if active_now {
                        let _ = tx.send(CaptureEvent::MouseButton { button, pressed });
                    }
                }
            }
            rdev::EventType::Wheel { delta_x, delta_y } => {
                if active_now {
                    let _ = tx.send(CaptureEvent::MouseWheel {
                        dx: delta_x.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
                        dy: delta_y.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
                    });
                }
            }
            rdev::EventType::KeyPress(k) | rdev::EventType::KeyRelease(k) => {
                let pressed = matches!(event.event_type, rdev::EventType::KeyPress(_));
                match k {
                    rdev::Key::ShiftLeft | rdev::Key::ShiftRight => st.mods.shift = pressed,
                    rdev::Key::ControlLeft | rdev::Key::ControlRight => st.mods.ctrl = pressed,
                    rdev::Key::Alt | rdev::Key::AltGr => st.mods.alt = pressed,
                    rdev::Key::MetaLeft | rdev::Key::MetaRight => st.mods.meta = pressed,
                    _ => {}
                }
                if active_now {
                    if let Some(hid) = keymap::rdev_key_to_hid(k) {
                        let _ = tx.send(CaptureEvent::Key {
                            key: KeyCode(hid),
                            pressed,
                            modifiers: st.mods,
                        });
                    }
                }
            }
        }

        if active_now {
            None
        } else {
            Some(passthrough_event)
        }
    };

    if let Err(e) = rdev::grab(cb) {
        tracing::error!("rdev grab failed: {e:?}");
    }
}
