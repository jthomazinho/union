//! Global input capture.
//!
//! Uses `rdev::grab` which gives us a callback per OS-level event with the
//! ability to consume (pass-through vs swallow). On macOS this is backed by
//! `CGEventTap`; on Linux/X11 by `XGrabPointer`/`XGrabKeyboard` via the
//! libinput shim; on Windows by `SetWindowsHookEx` with the **caveat** that
//! Windows low-level hooks cannot truly consume events from elevated
//! processes — that's a documented MVP limitation.
//!
//! Events are always forwarded over the channel (so the server can detect
//! edge crossings and hotkeys even while the user controls the local
//! machine). Whether the OS sees the event is controlled by:
//!  - `capturing` — when true, all input is swallowed (used while remote
//!    focus is active so the physical cursor stays put on the server box);
//!  - the embedded hotkey check — focus-cycle hotkeys are always swallowed
//!    so they don't leak into other apps.

mod keymap;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use protocol::{KeyCode, Modifiers, MouseButton};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy)]
pub enum CaptureEvent {
    /// `dx`, `dy` are deltas since the previous event (0 on the first one);
    /// `x`, `y` are the absolute cursor position the OS just reported.
    MouseMove {
        dx: i32,
        dy: i32,
        x: i32,
        y: i32,
    },
    MouseButton {
        button: MouseButton,
        pressed: bool,
    },
    MouseWheel {
        dx: i16,
        dy: i16,
    },
    Key {
        key: KeyCode,
        pressed: bool,
        modifiers: Modifiers,
    },
}

/// Hotkey predicate evaluated inside the capture callback. The server passes
/// this in so the callback can decide to swallow the hotkey before it reaches
/// other applications (without it, `Ctrl+Alt+→` would also fire whatever the
/// foreground app binds to that combo).
#[derive(Debug, Clone, Copy)]
pub struct HotkeyMatch {
    pub cycle_forward_key: u16,
    pub cycle_backward_key: u16,
    pub require_ctrl: bool,
    pub require_alt: bool,
    pub require_meta: bool,
}

impl HotkeyMatch {
    fn is_hotkey(&self, hid: u16, mods: Modifiers) -> bool {
        // HID 0 is reserved; treat it as "no hotkey configured" so the client
        // can pass a disabled HotkeyMatch.
        if hid == 0 || (self.cycle_forward_key == 0 && self.cycle_backward_key == 0) {
            return false;
        }
        if self.require_ctrl && !mods.ctrl {
            return false;
        }
        if self.require_alt && !mods.alt {
            return false;
        }
        if self.require_meta && !mods.meta {
            return false;
        }
        hid == self.cycle_forward_key || hid == self.cycle_backward_key
    }

    /// HotkeyMatch that never matches anything. Used by the client which
    /// only needs absolute mouse position for edge detection.
    pub fn disabled() -> Self {
        Self {
            cycle_forward_key: 0,
            cycle_backward_key: 0,
            require_ctrl: false,
            require_alt: false,
            require_meta: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("init: {0}")]
    Init(String),
    #[error("permission denied — accessibility/uinput access required")]
    PermissionDenied,
}

#[derive(Clone)]
pub struct CaptureControl {
    capturing: Arc<AtomicBool>,
}

impl CaptureControl {
    pub fn set_capturing(&self, on: bool) {
        self.capturing.store(on, Ordering::Release);
    }
    pub fn is_capturing(&self) -> bool {
        self.capturing.load(Ordering::Acquire)
    }
    /// Detached control with no backing capture thread; safe to call but
    /// state changes have no observable effect. Used by relay-only mode.
    pub fn dummy() -> Self {
        Self {
            capturing: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub struct CaptureHandle {
    pub events: mpsc::UnboundedReceiver<CaptureEvent>,
    pub control: CaptureControl,
}

/// Axis-aligned bounding box that covers every monitor attached to the
/// local machine, expressed in the same coordinate space the OS hands to
/// `rdev::EventType::MouseMove`. Use this — not the primary monitor — to
/// decide whether the cursor crossed an outer screen edge.
#[derive(Debug, Clone, Copy)]
pub struct VirtualBounds {
    pub min_x: i32,
    pub min_y: i32,
    pub max_x: i32,
    pub max_y: i32,
}

impl VirtualBounds {
    pub const fn width(self) -> i32 {
        self.max_x - self.min_x
    }
    pub const fn height(self) -> i32 {
        self.max_y - self.min_y
    }
    /// Fallback used when the OS query fails.
    pub const fn fallback() -> Self {
        Self {
            min_x: 0,
            min_y: 0,
            max_x: 1920,
            max_y: 1080,
        }
    }
}

/// Enumerate every monitor and return their union as a bounding box.
/// Returns `None` if the OS query fails (no monitors, headless, etc.).
pub fn virtual_bounds() -> Option<VirtualBounds> {
    let displays = display_info::DisplayInfo::all().ok()?;
    if displays.is_empty() {
        return None;
    }
    let mut min_x = i32::MAX;
    let mut min_y = i32::MAX;
    let mut max_x = i32::MIN;
    let mut max_y = i32::MIN;
    for d in displays {
        let x = d.x;
        let y = d.y;
        let w = d.width as i32;
        let h = d.height as i32;
        if x < min_x {
            min_x = x;
        }
        if y < min_y {
            min_y = y;
        }
        if x + w > max_x {
            max_x = x + w;
        }
        if y + h > max_y {
            max_y = y + h;
        }
    }
    Some(VirtualBounds {
        min_x,
        min_y,
        max_x,
        max_y,
    })
}

/// Primary display size in pixels. Used by clients to advertise their
/// canvas size to the server; absolute cursor positioning still happens in
/// primary-display coordinates because that's what `enigo::move_mouse` uses.
pub fn primary_display_size() -> Option<(u32, u32)> {
    rdev::display_size().ok().map(|(w, h)| (w as u32, h as u32))
}

/// Spawn the OS-native capture thread. The thread runs for the lifetime of
/// the process — `rdev::grab` blocks forever.
pub fn start_capture(hotkey: HotkeyMatch) -> Result<CaptureHandle, CaptureError> {
    let (tx, rx) = mpsc::unbounded_channel();
    let capturing = Arc::new(AtomicBool::new(false));
    let capturing_thread = capturing.clone();

    std::thread::Builder::new()
        .name("input-capture".into())
        .spawn(move || run_grab_loop(capturing_thread, hotkey, tx))
        .map_err(|e| CaptureError::Init(e.to_string()))?;

    Ok(CaptureHandle {
        events: rx,
        control: CaptureControl { capturing },
    })
}

fn run_grab_loop(
    capturing: Arc<AtomicBool>,
    hotkey: HotkeyMatch,
    tx: mpsc::UnboundedSender<CaptureEvent>,
) {
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
        let capturing_now = capturing.load(Ordering::Acquire);
        let mut st = state.lock().expect("capture state poisoned");

        let mut swallow_this = capturing_now;

        match event.event_type {
            rdev::EventType::MouseMove { x, y } => {
                let (dx, dy) = match st.last_pos {
                    Some((lx, ly)) => ((x - lx) as i32, (y - ly) as i32),
                    None => (0, 0),
                };
                st.last_pos = Some((x, y));
                let _ = tx.send(CaptureEvent::MouseMove {
                    dx,
                    dy,
                    x: x as i32,
                    y: y as i32,
                });
            }
            rdev::EventType::ButtonPress(b) | rdev::EventType::ButtonRelease(b) => {
                let pressed = matches!(event.event_type, rdev::EventType::ButtonPress(_));
                if let Some(button) = keymap::rdev_button_to_proto(b) {
                    let _ = tx.send(CaptureEvent::MouseButton { button, pressed });
                }
            }
            rdev::EventType::Wheel { delta_x, delta_y } => {
                let _ = tx.send(CaptureEvent::MouseWheel {
                    dx: delta_x.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
                    dy: delta_y.clamp(i16::MIN as i64, i16::MAX as i64) as i16,
                });
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
                if let Some(hid) = keymap::rdev_key_to_hid(k) {
                    if pressed && hotkey.is_hotkey(hid, st.mods) {
                        // Always swallow the cycle hotkey so foreground apps
                        // don't see Ctrl+Alt+→ as a real keystroke.
                        swallow_this = true;
                    }
                    let _ = tx.send(CaptureEvent::Key {
                        key: KeyCode(hid),
                        pressed,
                        modifiers: st.mods,
                    });
                }
            }
        }

        if swallow_this {
            None
        } else {
            Some(passthrough_event)
        }
    };

    if let Err(e) = rdev::grab(cb) {
        tracing::error!("rdev grab failed: {e:?}");
    }
}
