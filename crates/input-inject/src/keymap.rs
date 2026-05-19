//! HID Usage ID (page 0x07) → `enigo::Key` translation.
//!
//! Covers the common subset: letters, digits (top row), punctuation,
//! navigation, function keys, modifiers, and a few extras. Anything outside
//! the map returns `None`; the caller drops the event.

use enigo::Key;

pub fn hid_to_enigo(usage: u16, shift: bool) -> Option<Key> {
    use Key::*;
    Some(match usage {
        // Letters a..z (HID 0x04..0x1D) → Unicode lower/upper based on shift.
        0x04..=0x1D => {
            let base = (b'a' + (usage - 0x04) as u8) as char;
            Unicode(if shift {
                base.to_ascii_uppercase()
            } else {
                base
            })
        }
        // Digits 1..0 top row (HID 0x1E..0x27) → respect shift via OS layout
        // by sending the literal char; OS layouts that produce different
        // shifted glyphs will yield those.
        0x1E => Unicode(if shift { '!' } else { '1' }),
        0x1F => Unicode(if shift { '@' } else { '2' }),
        0x20 => Unicode(if shift { '#' } else { '3' }),
        0x21 => Unicode(if shift { '$' } else { '4' }),
        0x22 => Unicode(if shift { '%' } else { '5' }),
        0x23 => Unicode(if shift { '^' } else { '6' }),
        0x24 => Unicode(if shift { '&' } else { '7' }),
        0x25 => Unicode(if shift { '*' } else { '8' }),
        0x26 => Unicode(if shift { '(' } else { '9' }),
        0x27 => Unicode(if shift { ')' } else { '0' }),

        0x28 => Return,
        0x29 => Escape,
        0x2A => Backspace,
        0x2B => Tab,
        0x2C => Space,
        0x2D => Unicode(if shift { '_' } else { '-' }),
        0x2E => Unicode(if shift { '+' } else { '=' }),
        0x2F => Unicode(if shift { '{' } else { '[' }),
        0x30 => Unicode(if shift { '}' } else { ']' }),
        0x31 => Unicode(if shift { '|' } else { '\\' }),
        0x33 => Unicode(if shift { ':' } else { ';' }),
        0x34 => Unicode(if shift { '"' } else { '\'' }),
        0x35 => Unicode(if shift { '~' } else { '`' }),
        0x36 => Unicode(if shift { '<' } else { ',' }),
        0x37 => Unicode(if shift { '>' } else { '.' }),
        0x38 => Unicode(if shift { '?' } else { '/' }),

        0x39 => CapsLock,

        // Function keys
        0x3A => F1,
        0x3B => F2,
        0x3C => F3,
        0x3D => F4,
        0x3E => F5,
        0x3F => F6,
        0x40 => F7,
        0x41 => F8,
        0x42 => F9,
        0x43 => F10,
        0x44 => F11,
        0x45 => F12,

        // 0x49 (Insert) not exposed by enigo on all backends; skip.
        0x4A => Home,
        0x4B => PageUp,
        0x4C => Delete,
        0x4D => End,
        0x4E => PageDown,

        0x4F => RightArrow,
        0x50 => LeftArrow,
        0x51 => DownArrow,
        0x52 => UpArrow,

        // Modifiers (we mostly handle these via sync_modifiers, but include
        // them so an explicit left/right modifier event still works).
        0xE0 => Control,
        0xE1 => Shift,
        0xE2 => Alt,
        0xE3 => Meta,
        0xE4 => Control,
        0xE5 => Shift,
        0xE6 => Alt,
        0xE7 => Meta,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_map_lower_and_upper() {
        assert!(matches!(hid_to_enigo(0x04, false), Some(Key::Unicode('a'))));
        assert!(matches!(hid_to_enigo(0x04, true), Some(Key::Unicode('A'))));
        assert!(matches!(hid_to_enigo(0x1D, false), Some(Key::Unicode('z'))));
    }

    #[test]
    fn arrows_map() {
        assert!(matches!(hid_to_enigo(0x4F, false), Some(Key::RightArrow)));
        assert!(matches!(hid_to_enigo(0x52, false), Some(Key::UpArrow)));
    }

    #[test]
    fn unknown_returns_none() {
        assert!(hid_to_enigo(0xFFFF, false).is_none());
    }
}
