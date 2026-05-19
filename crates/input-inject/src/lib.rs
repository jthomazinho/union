//! Cross-platform input event injection, implemented on top of `enigo`.
//!
//! The wire protocol carries HID Usage IDs (page 0x07) for key codes so that
//! the same payload works on macOS, Linux/X11, and Windows. This module
//! translates HID codes to `enigo::Key` variants for the common subset; the
//! rest fall through to `Key::Unicode` when possible or are logged and dropped.

mod keymap;

use enigo::{Axis, Button, Coordinate, Direction, Enigo, Keyboard as _, Mouse as _, Settings};
use protocol::{KeyCode, Modifiers, MouseButton};

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("backend init: {0}")]
    Init(String),
    #[error("inject: {0}")]
    Inject(String),
}

/// Not `Send` on purpose: the macOS backend wraps Objective-C objects and
/// must stay pinned to one thread. The daemon owns an injector inside a
/// dedicated `std::thread` and receives commands via a channel.
pub trait InputInjector {
    fn mouse_move_relative(&mut self, dx: i32, dy: i32) -> Result<(), InjectError>;
    fn mouse_move_absolute(&mut self, x: i32, y: i32) -> Result<(), InjectError>;
    fn mouse_button(&mut self, button: MouseButton, pressed: bool) -> Result<(), InjectError>;
    fn mouse_wheel(&mut self, dx: i16, dy: i16) -> Result<(), InjectError>;
    fn key(&mut self, key: KeyCode, pressed: bool, modifiers: Modifiers)
        -> Result<(), InjectError>;
    /// Release every modifier we believe to be held. Called on focus change
    /// and disconnect so a session that died mid-keypress doesn't leave
    /// the local OS in a "stuck Ctrl" state.
    fn release_all_modifiers(&mut self) -> Result<(), InjectError>;
}

pub struct PlatformInjector {
    enigo: Enigo,
    // Track currently held modifiers so we only press/release on transitions.
    held: Modifiers,
}

impl PlatformInjector {
    pub fn new() -> Result<Self, InjectError> {
        let enigo =
            Enigo::new(&Settings::default()).map_err(|e| InjectError::Init(e.to_string()))?;
        Ok(Self {
            enigo,
            held: Modifiers::default(),
        })
    }

    fn sync_modifiers(&mut self, target: Modifiers) -> Result<(), InjectError> {
        use enigo::Key;
        let pairs = [
            (Key::Shift, self.held.shift, target.shift),
            (Key::Control, self.held.ctrl, target.ctrl),
            (Key::Alt, self.held.alt, target.alt),
            (Key::Meta, self.held.meta, target.meta),
        ];
        for (k, was, now) in pairs {
            if was == now {
                continue;
            }
            let dir = if now {
                Direction::Press
            } else {
                Direction::Release
            };
            self.enigo
                .key(k, dir)
                .map_err(|e| InjectError::Inject(e.to_string()))?;
        }
        self.held = target;
        Ok(())
    }
}

impl InputInjector for PlatformInjector {
    fn mouse_move_relative(&mut self, dx: i32, dy: i32) -> Result<(), InjectError> {
        self.enigo
            .move_mouse(dx, dy, Coordinate::Rel)
            .map_err(|e| InjectError::Inject(e.to_string()))
    }

    fn mouse_move_absolute(&mut self, x: i32, y: i32) -> Result<(), InjectError> {
        self.enigo
            .move_mouse(x, y, Coordinate::Abs)
            .map_err(|e| InjectError::Inject(e.to_string()))
    }

    fn mouse_button(&mut self, button: MouseButton, pressed: bool) -> Result<(), InjectError> {
        let btn = match button {
            MouseButton::Left => Button::Left,
            MouseButton::Right => Button::Right,
            MouseButton::Middle => Button::Middle,
            // Back/Forward aren't uniformly supported by enigo across all
            // backends; skip rather than fail the whole stream.
            MouseButton::Back | MouseButton::Forward => {
                tracing::debug!("dropping unsupported mouse button {:?}", button);
                return Ok(());
            }
        };
        let dir = if pressed {
            Direction::Press
        } else {
            Direction::Release
        };
        self.enigo
            .button(btn, dir)
            .map_err(|e| InjectError::Inject(e.to_string()))
    }

    fn mouse_wheel(&mut self, dx: i16, dy: i16) -> Result<(), InjectError> {
        if dx != 0 {
            self.enigo
                .scroll(dx as i32, Axis::Horizontal)
                .map_err(|e| InjectError::Inject(e.to_string()))?;
        }
        if dy != 0 {
            self.enigo
                .scroll(dy as i32, Axis::Vertical)
                .map_err(|e| InjectError::Inject(e.to_string()))?;
        }
        Ok(())
    }

    fn key(
        &mut self,
        key: KeyCode,
        pressed: bool,
        modifiers: Modifiers,
    ) -> Result<(), InjectError> {
        self.sync_modifiers(modifiers)?;
        let Some(ek) = keymap::hid_to_enigo(key.0, modifiers.shift) else {
            tracing::debug!("dropping unmapped key 0x{:04x}", key.0);
            return Ok(());
        };
        let dir = if pressed {
            Direction::Press
        } else {
            Direction::Release
        };
        self.enigo
            .key(ek, dir)
            .map_err(|e| InjectError::Inject(e.to_string()))
    }

    fn release_all_modifiers(&mut self) -> Result<(), InjectError> {
        self.sync_modifiers(Modifiers::default())
    }
}

pub fn new_injector() -> Result<Box<dyn InputInjector>, InjectError> {
    Ok(Box::new(PlatformInjector::new()?))
}

/// Run the injector on a dedicated OS thread that owns it (since the macOS
/// backend isn't `Send`). The returned channel sender can be used from any
/// task to dispatch commands.
pub fn spawn_injector_thread() -> std::sync::mpsc::Sender<InjectCmd> {
    let (tx, rx) = std::sync::mpsc::channel::<InjectCmd>();
    std::thread::Builder::new()
        .name("input-inject".into())
        .spawn(move || {
            let mut injector = match PlatformInjector::new() {
                Ok(i) => i,
                Err(e) => {
                    tracing::error!("injector init failed: {e}");
                    return;
                }
            };
            while let Ok(cmd) = rx.recv() {
                if let Err(e) = apply(&mut injector, cmd) {
                    tracing::warn!("inject failed: {e}");
                }
            }
        })
        .expect("spawn injector thread");
    tx
}

#[derive(Debug, Clone)]
pub enum InjectCmd {
    MoveRel(i32, i32),
    MoveAbs(i32, i32),
    Button(MouseButton, bool),
    Wheel(i16, i16),
    Key {
        key: KeyCode,
        pressed: bool,
        modifiers: Modifiers,
    },
    /// Force-release every modifier we believe to be held. Sent on focus
    /// loss and on session teardown to avoid "stuck Ctrl" after a crash.
    ReleaseAllModifiers,
}

fn apply(inj: &mut PlatformInjector, cmd: InjectCmd) -> Result<(), InjectError> {
    match cmd {
        InjectCmd::MoveRel(dx, dy) => inj.mouse_move_relative(dx, dy),
        InjectCmd::MoveAbs(x, y) => inj.mouse_move_absolute(x, y),
        InjectCmd::Button(b, p) => inj.mouse_button(b, p),
        InjectCmd::Wheel(dx, dy) => inj.mouse_wheel(dx, dy),
        InjectCmd::Key {
            key,
            pressed,
            modifiers,
        } => inj.key(key, pressed, modifiers),
        InjectCmd::ReleaseAllModifiers => inj.release_all_modifiers(),
    }
}
