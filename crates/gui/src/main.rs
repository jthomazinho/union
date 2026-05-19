//! egui control panel for Union.
//!
//! Two modes (Server / Client). Each one:
//!  - loads any existing config from the standard config dir on startup so the
//!    form reflects what would actually run;
//!  - validates required fields before allowing Start;
//!  - launches the matching binary as a child process, tails its stdout/stderr
//!    into an in-app log buffer, and detects exits in the background.
//!
//! The server tab also surfaces the auto-generated cert fingerprint (read
//! from `<cert_dir>/server.crt`) so the user can copy it into a client config
//! without digging through logs.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use eframe::egui;
use serde::Deserialize;

const APP_TITLE: &str = "Union";
const LOG_BUFFER_LINES: usize = 400;

fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt::init();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 620.0])
            .with_title(APP_TITLE),
        ..Default::default()
    };
    eframe::run_native(APP_TITLE, opts, Box::new(|_cc| Ok(Box::new(App::new()))))
}

#[derive(Default)]
struct App {
    mode: Mode,
    server: ServerForm,
    client: ClientForm,
    daemon: DaemonHandle,
    status: String,
    server_fingerprint: Option<String>,
    test_result: Arc<Mutex<TestStatus>>,
    runtime_snapshot: Option<StatusSnapshot>,
    runtime_snapshot_loaded_at: Option<std::time::Instant>,
}

#[derive(Deserialize, Clone)]
struct StatusSnapshot {
    pid: u32,
    timestamp_unix: u64,
    fingerprint_hex: String,
    listening_on: String,
    focus: FocusSnapshot,
    clients: Vec<ClientSnapshot>,
    metrics: MetricsSnapshot,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
enum FocusSnapshot {
    Local,
    Remote(String),
}

#[derive(Deserialize, Clone)]
struct ClientSnapshot {
    hostname: String,
    position: String,
    screen: Option<(u32, u32)>,
}

#[derive(Deserialize, Clone, Copy)]
struct MetricsSnapshot {
    auth_failures: u64,
    focus_switches: u64,
    sessions_opened: u64,
    clipboard_text_bytes: u64,
    clipboard_image_bytes: u64,
}

#[derive(Default, Clone)]
enum TestStatus {
    #[default]
    Idle,
    Running,
    Ok(String),
    Err(String),
}

#[derive(PartialEq, Eq, Default, Clone, Copy)]
enum Mode {
    #[default]
    Server,
    Client,
}

struct ServerForm {
    port: u16,
    bind: String,
    psk: String,
    cert_dir: String,
    clipboard_limit_kb: u64,
    notify_on_focus: bool,
    overlay_on_focus: bool,
    hotkey: HotkeyForm,
    layout: Vec<LayoutEntry>,
    new_layout_host: String,
    new_layout_position: Position,
}
impl Default for ServerForm {
    fn default() -> Self {
        Self {
            port: protocol::DEFAULT_PORT,
            bind: "0.0.0.0".into(),
            psk: String::new(),
            cert_dir: default_cert_dir().display().to_string(),
            clipboard_limit_kb: (clipboard_sync::DEFAULT_LIMIT_BYTES / 1024) as u64,
            notify_on_focus: true,
            overlay_on_focus: false,
            hotkey: HotkeyForm::default(),
            layout: Vec::new(),
            new_layout_host: String::new(),
            new_layout_position: Position::Right,
        }
    }
}

#[derive(Clone)]
struct HotkeyForm {
    forward_label: String,
    backward_label: String,
    require_ctrl: bool,
    require_alt: bool,
    require_meta: bool,
}
impl Default for HotkeyForm {
    fn default() -> Self {
        Self {
            forward_label: "RightArrow".into(),
            backward_label: "LeftArrow".into(),
            require_ctrl: true,
            require_alt: true,
            require_meta: false,
        }
    }
}

#[derive(Clone)]
struct LayoutEntry {
    hostname: String,
    position: Position,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    Left,
    Right,
    Above,
    Below,
}
impl Position {
    const ALL: [Position; 4] = [
        Position::Left,
        Position::Right,
        Position::Above,
        Position::Below,
    ];
    fn as_str(self) -> &'static str {
        match self {
            Position::Left => "left",
            Position::Right => "right",
            Position::Above => "above",
            Position::Below => "below",
        }
    }
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "left" => Some(Position::Left),
            "right" => Some(Position::Right),
            "above" => Some(Position::Above),
            "below" => Some(Position::Below),
            _ => None,
        }
    }
}

/// HID Usage IDs (page 0x07) of keys we expose in the hotkey combobox. The
/// label is what the user sees; the u16 is what goes into the TOML.
const HOTKEY_KEYS: &[(&str, u16)] = &[
    ("RightArrow", 0x4F),
    ("LeftArrow", 0x50),
    ("DownArrow", 0x51),
    ("UpArrow", 0x52),
    ("F1", 0x3A),
    ("F2", 0x3B),
    ("F3", 0x3C),
    ("F4", 0x3D),
    ("F5", 0x3E),
    ("F6", 0x3F),
    ("F7", 0x40),
    ("F8", 0x41),
    ("F9", 0x42),
    ("F10", 0x43),
    ("F11", 0x44),
    ("F12", 0x45),
    ("Tab", 0x2B),
    ("Space", 0x2C),
];

fn key_label_for(hid: u16) -> String {
    HOTKEY_KEYS
        .iter()
        .find(|(_, v)| *v == hid)
        .map(|(l, _)| (*l).to_string())
        .unwrap_or_else(|| format!("0x{hid:04X}"))
}

fn hid_for(label: &str) -> u16 {
    HOTKEY_KEYS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, v)| *v)
        .unwrap_or(0x4F)
}

fn key_combo(ui: &mut egui::Ui, id: &str, selected: &mut String) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected.clone())
        .show_ui(ui, |ui| {
            for (label, _) in HOTKEY_KEYS {
                ui.selectable_value(selected, (*label).to_string(), *label);
            }
        });
}

fn position_combo(ui: &mut egui::Ui, id: &str, selected: &mut Position) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected.as_str())
        .show_ui(ui, |ui| {
            for p in Position::ALL {
                ui.selectable_value(selected, p, p.as_str());
            }
        });
}

struct ClientForm {
    discover: bool,
    server_addr: String,
    port: u16,
    hostname: String,
    psk: String,
    fingerprint_hex: String,
    clipboard_limit_kb: u64,
    notify_on_focus: bool,
    overlay_on_focus: bool,
}
impl Default for ClientForm {
    fn default() -> Self {
        Self {
            discover: false,
            server_addr: "127.0.0.1".into(),
            port: protocol::DEFAULT_PORT,
            hostname: hostname_default(),
            psk: String::new(),
            fingerprint_hex: String::new(),
            clipboard_limit_kb: (clipboard_sync::DEFAULT_LIMIT_BYTES / 1024) as u64,
            notify_on_focus: true,
            overlay_on_focus: false,
        }
    }
}

impl App {
    fn new() -> Self {
        let mut app = Self::default();
        app.reload_from_disk();
        app
    }

    fn reload_from_disk(&mut self) {
        let dir = config_dir();
        if let Ok(text) = std::fs::read_to_string(dir.join("server.toml")) {
            if let Ok(v) = text.parse::<toml::Value>() {
                if let Some(p) = v.get("port").and_then(|x| x.as_integer()) {
                    self.server.port = p as u16;
                }
                if let Some(s) = v.get("bind").and_then(|x| x.as_str()) {
                    self.server.bind = s.to_string();
                }
                if let Some(s) = v.get("psk").and_then(|x| x.as_str()) {
                    self.server.psk = s.to_string();
                }
                if let Some(s) = v.get("cert_dir").and_then(|x| x.as_str()) {
                    self.server.cert_dir = s.to_string();
                }
                if let Some(n) = v.get("clipboard_limit_bytes").and_then(|x| x.as_integer()) {
                    self.server.clipboard_limit_kb = (n as u64) / 1024;
                }
                if let Some(b) = v.get("notify_on_focus").and_then(|x| x.as_bool()) {
                    self.server.notify_on_focus = b;
                }
                if let Some(b) = v.get("overlay_on_focus").and_then(|x| x.as_bool()) {
                    self.server.overlay_on_focus = b;
                }
                if let Some(hk) = v.get("hotkey").and_then(|x| x.as_table()) {
                    if let Some(n) = hk.get("cycle_forward_key").and_then(|x| x.as_integer()) {
                        self.server.hotkey.forward_label = key_label_for(n as u16);
                    }
                    if let Some(n) = hk.get("cycle_backward_key").and_then(|x| x.as_integer()) {
                        self.server.hotkey.backward_label = key_label_for(n as u16);
                    }
                    if let Some(b) = hk.get("require_ctrl").and_then(|x| x.as_bool()) {
                        self.server.hotkey.require_ctrl = b;
                    }
                    if let Some(b) = hk.get("require_alt").and_then(|x| x.as_bool()) {
                        self.server.hotkey.require_alt = b;
                    }
                    if let Some(b) = hk.get("require_meta").and_then(|x| x.as_bool()) {
                        self.server.hotkey.require_meta = b;
                    }
                }
                if let Some(lay) = v.get("layout").and_then(|x| x.as_table()) {
                    self.server.layout.clear();
                    for (host, entry) in lay {
                        let pos = entry
                            .as_table()
                            .and_then(|t| t.get("position"))
                            .and_then(|x| x.as_str())
                            .and_then(Position::from_str)
                            .unwrap_or(Position::Right);
                        self.server.layout.push(LayoutEntry {
                            hostname: host.clone(),
                            position: pos,
                        });
                    }
                }
            }
        }
        if let Ok(text) = std::fs::read_to_string(dir.join("client.toml")) {
            if let Ok(v) = text.parse::<toml::Value>() {
                if let Some(b) = v.get("discover").and_then(|x| x.as_bool()) {
                    self.client.discover = b;
                }
                if let Some(s) = v.get("server_addr").and_then(|x| x.as_str()) {
                    self.client.server_addr = s.to_string();
                }
                if let Some(p) = v.get("port").and_then(|x| x.as_integer()) {
                    self.client.port = p as u16;
                }
                if let Some(s) = v.get("hostname").and_then(|x| x.as_str()) {
                    self.client.hostname = s.to_string();
                }
                if let Some(s) = v.get("psk").and_then(|x| x.as_str()) {
                    self.client.psk = s.to_string();
                }
                if let Some(s) = v.get("server_fingerprint_hex").and_then(|x| x.as_str()) {
                    self.client.fingerprint_hex = s.to_string();
                }
                if let Some(n) = v.get("clipboard_limit_bytes").and_then(|x| x.as_integer()) {
                    self.client.clipboard_limit_kb = (n as u64) / 1024;
                }
                if let Some(b) = v.get("notify_on_focus").and_then(|x| x.as_bool()) {
                    self.client.notify_on_focus = b;
                }
                if let Some(b) = v.get("overlay_on_focus").and_then(|x| x.as_bool()) {
                    self.client.overlay_on_focus = b;
                }
            }
        }
        self.refresh_fingerprint();
    }

    fn refresh_runtime_snapshot(&mut self) {
        let path = config_dir().join("runtime").join("status.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(snap) = serde_json::from_str::<StatusSnapshot>(&text) {
                self.runtime_snapshot = Some(snap);
                self.runtime_snapshot_loaded_at = Some(std::time::Instant::now());
            }
        }
    }

    fn refresh_fingerprint(&mut self) {
        let path = PathBuf::from(&self.server.cert_dir).join("server.crt");
        self.server_fingerprint = std::fs::read_to_string(&path)
            .ok()
            .and_then(|pem| union_tls::cert::fingerprint_sha256(&pem).ok())
            .map(hex::encode);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Periodic poll: detect daemon exit, repaint with fresh logs.
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        self.daemon.reap_if_exited();
        // Pick up the latest status snapshot at most once a second.
        let need_snap = self
            .runtime_snapshot_loaded_at
            .map(|t| t.elapsed().as_millis() > 800)
            .unwrap_or(true);
        if need_snap {
            self.refresh_runtime_snapshot();
        }

        egui::TopBottomPanel::top("nav").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Union");
                ui.separator();
                ui.radio_value(&mut self.mode, Mode::Server, "Server");
                ui.radio_value(&mut self.mode, Mode::Client, "Client");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(self.daemon.status_text());
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.mode {
                Mode::Server => self.draw_server(ui),
                Mode::Client => self.draw_client(ui),
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Reload config").clicked() {
                    self.reload_from_disk();
                    self.status = "Config reloaded from disk".into();
                }
                if ui.button("Save").clicked() {
                    self.status = match self.save_config() {
                        Ok(p) => format!("Saved to {}", p.display()),
                        Err(e) => format!("Save failed: {e}"),
                    };
                }
                if self.daemon.is_running() {
                    if ui.button("Stop daemon").clicked() {
                        self.daemon.stop();
                        self.status = "Daemon stopped".into();
                    }
                } else {
                    let enabled = self.validate().is_ok();
                    let resp = ui.add_enabled(enabled, egui::Button::new("Start daemon"));
                    if let Err(e) = self.validate() {
                        resp.on_hover_text(format!("Cannot start: {e}"));
                    } else if resp.clicked() {
                        self.status = match self.start_daemon() {
                            Ok(()) => "Daemon started".into(),
                            Err(e) => format!("Start failed: {e}"),
                        };
                    }
                }
            });

            ui.add_space(4.0);
            ui.label(&self.status);

            ui.separator();
            ui.label(egui::RichText::new("Logs").strong());
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .max_height(220.0)
                .show(ui, |ui| {
                    let logs = self.daemon.snapshot_logs();
                    if logs.is_empty() {
                        ui.weak("(no daemon output yet)");
                    } else {
                        ui.add(
                            egui::TextEdit::multiline(&mut logs.as_str())
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                    }
                });
        });
    }
}

impl App {
    fn draw_server(&mut self, ui: &mut egui::Ui) {
        ui.label("This machine owns the physical keyboard/mouse.");
        ui.add_space(8.0);
        egui::Grid::new("server-grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label("Bind:");
                ui.text_edit_singleline(&mut self.server.bind);
                ui.end_row();
                ui.label("Port:");
                ui.add(egui::DragValue::new(&mut self.server.port).range(1..=65535));
                ui.end_row();
                ui.label("Passphrase (PSK):");
                ui.add(egui::TextEdit::singleline(&mut self.server.psk).password(true));
                ui.end_row();
                ui.label("Cert directory:");
                if ui.text_edit_singleline(&mut self.server.cert_dir).changed() {
                    self.refresh_fingerprint();
                }
                ui.end_row();
                ui.label("Clipboard limit (KB):");
                ui.add(egui::DragValue::new(&mut self.server.clipboard_limit_kb));
                ui.end_row();
                ui.label("Notify on focus change:");
                ui.checkbox(&mut self.server.notify_on_focus, "");
                ui.end_row();
                ui.label("Overlay banner on focus:");
                ui.checkbox(&mut self.server.overlay_on_focus, "");
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Fingerprint (SHA-256):");
            match &self.server_fingerprint {
                Some(fp) => {
                    let mut shown = fp.clone();
                    ui.add(
                        egui::TextEdit::singleline(&mut shown)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                }
                None => {
                    ui.weak("(not yet generated — start the daemon once)");
                }
            }
        });

        ui.add_space(12.0);
        ui.collapsing("Hotkey (manual focus cycle)", |ui| {
            egui::Grid::new("hotkey-grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Forward key:");
                    key_combo(ui, "fwd-key", &mut self.server.hotkey.forward_label);
                    ui.end_row();
                    ui.label("Backward key:");
                    key_combo(ui, "back-key", &mut self.server.hotkey.backward_label);
                    ui.end_row();
                    ui.label("Modifiers:");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.server.hotkey.require_ctrl, "Ctrl");
                        ui.checkbox(&mut self.server.hotkey.require_alt, "Alt");
                        ui.checkbox(&mut self.server.hotkey.require_meta, "Meta");
                    });
                    ui.end_row();
                });
        });

        ui.add_space(12.0);
        ui.collapsing("Layout 2D (client positions)", |ui| {
            ui.weak("Each client hostname maps to a position relative to this server. Clients without an entry default to `right`.");
            ui.add_space(4.0);
            let mut to_remove: Option<usize> = None;
            for (i, entry) in self.server.layout.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut entry.hostname).desired_width(160.0));
                    position_combo(ui, &format!("pos-{i}"), &mut entry.position);
                    if ui.button("Remove").clicked() {
                        to_remove = Some(i);
                    }
                });
            }
            if let Some(i) = to_remove {
                self.server.layout.remove(i);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.server.new_layout_host)
                        .hint_text("hostname")
                        .desired_width(160.0),
                );
                position_combo(ui, "new-pos", &mut self.server.new_layout_position);
                let can_add = !self.server.new_layout_host.trim().is_empty()
                    && !self
                        .server
                        .layout
                        .iter()
                        .any(|e| e.hostname == self.server.new_layout_host.trim());
                if ui.add_enabled(can_add, egui::Button::new("Add")).clicked() {
                    self.server.layout.push(LayoutEntry {
                        hostname: self.server.new_layout_host.trim().to_string(),
                        position: self.server.new_layout_position,
                    });
                    self.server.new_layout_host.clear();
                }
            });
        });

        ui.add_space(12.0);
        ui.collapsing("Runtime status", |ui| match &self.runtime_snapshot {
            None => {
                ui.weak("No status snapshot yet — start the daemon to populate.");
            }
            Some(snap) => {
                let age = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0))
                .saturating_sub(snap.timestamp_unix);
                let stale = age > 5;
                if stale {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 150, 90),
                        format!("snapshot stale ({age}s old)"),
                    );
                }
                egui::Grid::new("runtime-grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("PID:");
                        ui.label(snap.pid.to_string());
                        ui.end_row();
                        ui.label("Listening on:");
                        ui.label(&snap.listening_on);
                        ui.end_row();
                        ui.label("Fingerprint:");
                        let mut fp = snap.fingerprint_hex.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut fp)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.end_row();
                        ui.label("Focus:");
                        let focus = match &snap.focus {
                            FocusSnapshot::Local => "local".into(),
                            FocusSnapshot::Remote(h) => format!("→ {h}"),
                        };
                        ui.label(focus);
                        ui.end_row();
                    });

                ui.add_space(6.0);
                ui.label(egui::RichText::new("Connected clients").strong());
                if snap.clients.is_empty() {
                    ui.weak("(none)");
                } else {
                    egui::Grid::new("clients-grid")
                        .num_columns(3)
                        .spacing([16.0, 2.0])
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("hostname").italics());
                            ui.label(egui::RichText::new("position").italics());
                            ui.label(egui::RichText::new("screen").italics());
                            ui.end_row();
                            for c in &snap.clients {
                                ui.label(&c.hostname);
                                ui.label(&c.position);
                                ui.label(match c.screen {
                                    Some((w, h)) => format!("{w}x{h}"),
                                    None => "—".into(),
                                });
                                ui.end_row();
                            }
                        });
                }

                ui.add_space(6.0);
                ui.label(egui::RichText::new("Metrics").strong());
                let m = &snap.metrics;
                egui::Grid::new("metrics-grid")
                    .num_columns(2)
                    .spacing([16.0, 2.0])
                    .show(ui, |ui| {
                        ui.label("sessions opened:");
                        ui.label(m.sessions_opened.to_string());
                        ui.end_row();
                        ui.label("focus switches:");
                        ui.label(m.focus_switches.to_string());
                        ui.end_row();
                        ui.label("auth failures:");
                        ui.label(m.auth_failures.to_string());
                        ui.end_row();
                        ui.label("clipboard text bytes:");
                        ui.label(human_bytes(m.clipboard_text_bytes));
                        ui.end_row();
                        ui.label("clipboard image bytes:");
                        ui.label(human_bytes(m.clipboard_image_bytes));
                        ui.end_row();
                    });
            }
        });
    }

    fn draw_client(&mut self, ui: &mut egui::Ui) {
        ui.label("This machine receives input from the server.");
        ui.add_space(8.0);

        ui.checkbox(
            &mut self.client.discover,
            "Discover server via mDNS (ignore address + fingerprint below)",
        );
        ui.add_space(6.0);

        egui::Grid::new("client-grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label("Server address:");
                ui.add_enabled(
                    !self.client.discover,
                    egui::TextEdit::singleline(&mut self.client.server_addr),
                );
                ui.end_row();
                ui.label("Port:");
                ui.add_enabled(
                    !self.client.discover,
                    egui::DragValue::new(&mut self.client.port).range(1..=65535),
                );
                ui.end_row();
                ui.label("Hostname (this machine):");
                ui.text_edit_singleline(&mut self.client.hostname);
                ui.end_row();
                ui.label("Passphrase (PSK):");
                ui.add(egui::TextEdit::singleline(&mut self.client.psk).password(true));
                ui.end_row();
                ui.label("Server fingerprint (hex):");
                ui.add_enabled(
                    !self.client.discover,
                    egui::TextEdit::singleline(&mut self.client.fingerprint_hex)
                        .font(egui::TextStyle::Monospace),
                );
                ui.end_row();
                ui.label("Clipboard limit (KB):");
                ui.add(egui::DragValue::new(&mut self.client.clipboard_limit_kb));
                ui.end_row();
                ui.label("Notify on focus change:");
                ui.checkbox(&mut self.client.notify_on_focus, "");
                ui.end_row();
                ui.label("Overlay banner on focus:");
                ui.checkbox(&mut self.client.overlay_on_focus, "");
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let running = matches!(*self.test_result.lock().unwrap(), TestStatus::Running);
            let enabled = self.validate().is_ok() && !running;
            if ui
                .add_enabled(enabled, egui::Button::new("Test connection"))
                .clicked()
            {
                if let Err(e) = self.start_test_connection() {
                    *self.test_result.lock().unwrap() = TestStatus::Err(e.to_string());
                }
            }
            match self.test_result.lock().unwrap().clone() {
                TestStatus::Idle => {}
                TestStatus::Running => {
                    ui.spinner();
                    ui.label("testing…");
                }
                TestStatus::Ok(msg) => {
                    ui.colored_label(egui::Color32::from_rgb(80, 170, 100), msg);
                }
                TestStatus::Err(msg) => {
                    ui.colored_label(egui::Color32::from_rgb(200, 90, 90), msg);
                }
            }
        });
    }

    fn validate(&self) -> anyhow::Result<()> {
        match self.mode {
            Mode::Server => {
                if self.server.psk.is_empty() {
                    anyhow::bail!("PSK must not be empty");
                }
            }
            Mode::Client => {
                if self.client.psk.is_empty() {
                    anyhow::bail!("PSK must not be empty");
                }
                if self.client.hostname.is_empty() {
                    anyhow::bail!("Hostname must not be empty");
                }
                if !self.client.discover {
                    if self.client.server_addr.is_empty() {
                        anyhow::bail!("Server address required (or enable discover)");
                    }
                    let fp = self.client.fingerprint_hex.trim().replace(':', "");
                    if fp.len() != 64 || hex::decode(&fp).is_err() {
                        anyhow::bail!("Fingerprint must be 64 hex chars");
                    }
                }
            }
        }
        Ok(())
    }

    fn save_config(&self) -> anyhow::Result<PathBuf> {
        let dir = config_dir();
        std::fs::create_dir_all(&dir)?;
        let (path, table) = match self.mode {
            Mode::Server => {
                let mut t = toml::value::Table::new();
                t.insert("port".into(), toml::Value::Integer(self.server.port.into()));
                t.insert("bind".into(), toml::Value::String(self.server.bind.clone()));
                t.insert("psk".into(), toml::Value::String(self.server.psk.clone()));
                t.insert(
                    "cert_dir".into(),
                    toml::Value::String(self.server.cert_dir.clone()),
                );
                t.insert(
                    "clipboard_limit_bytes".into(),
                    toml::Value::Integer((self.server.clipboard_limit_kb * 1024) as i64),
                );
                t.insert(
                    "notify_on_focus".into(),
                    toml::Value::Boolean(self.server.notify_on_focus),
                );
                t.insert(
                    "overlay_on_focus".into(),
                    toml::Value::Boolean(self.server.overlay_on_focus),
                );
                let mut hk = toml::value::Table::new();
                hk.insert(
                    "cycle_forward_key".into(),
                    toml::Value::Integer(hid_for(&self.server.hotkey.forward_label) as i64),
                );
                hk.insert(
                    "cycle_backward_key".into(),
                    toml::Value::Integer(hid_for(&self.server.hotkey.backward_label) as i64),
                );
                hk.insert(
                    "require_ctrl".into(),
                    toml::Value::Boolean(self.server.hotkey.require_ctrl),
                );
                hk.insert(
                    "require_alt".into(),
                    toml::Value::Boolean(self.server.hotkey.require_alt),
                );
                hk.insert(
                    "require_meta".into(),
                    toml::Value::Boolean(self.server.hotkey.require_meta),
                );
                t.insert("hotkey".into(), toml::Value::Table(hk));
                if !self.server.layout.is_empty() {
                    let mut lay = toml::value::Table::new();
                    for entry in &self.server.layout {
                        let mut e = toml::value::Table::new();
                        e.insert(
                            "position".into(),
                            toml::Value::String(entry.position.as_str().into()),
                        );
                        lay.insert(entry.hostname.clone(), toml::Value::Table(e));
                    }
                    t.insert("layout".into(), toml::Value::Table(lay));
                }
                (dir.join("server.toml"), t)
            }
            Mode::Client => {
                let mut t = toml::value::Table::new();
                t.insert(
                    "discover".into(),
                    toml::Value::Boolean(self.client.discover),
                );
                t.insert(
                    "server_addr".into(),
                    toml::Value::String(self.client.server_addr.clone()),
                );
                t.insert("port".into(), toml::Value::Integer(self.client.port.into()));
                t.insert(
                    "hostname".into(),
                    toml::Value::String(self.client.hostname.clone()),
                );
                t.insert("psk".into(), toml::Value::String(self.client.psk.clone()));
                t.insert(
                    "server_fingerprint_hex".into(),
                    toml::Value::String(self.client.fingerprint_hex.trim().to_string()),
                );
                t.insert(
                    "clipboard_limit_bytes".into(),
                    toml::Value::Integer((self.client.clipboard_limit_kb * 1024) as i64),
                );
                t.insert(
                    "notify_on_focus".into(),
                    toml::Value::Boolean(self.client.notify_on_focus),
                );
                t.insert(
                    "overlay_on_focus".into(),
                    toml::Value::Boolean(self.client.overlay_on_focus),
                );
                (dir.join("client.toml"), t)
            }
        };
        let text = toml::to_string_pretty(&toml::Value::Table(table))?;
        std::fs::write(&path, text)?;
        Ok(path)
    }

    fn start_test_connection(&mut self) -> anyhow::Result<()> {
        let config_path = self.save_config()?;
        let bin = sibling_binary("union-client");
        *self.test_result.lock().unwrap() = TestStatus::Running;
        let result = self.test_result.clone();
        thread::spawn(move || {
            let output = Command::new(&bin)
                .arg("--config")
                .arg(&config_path)
                .arg("--test-connection")
                .output();
            let status = match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    match out.status.code() {
                        Some(0) => TestStatus::Ok(if stdout.is_empty() {
                            "Handshake OK".into()
                        } else {
                            stdout
                        }),
                        Some(2) => TestStatus::Err(format!("Fingerprint mismatch: {stderr}")),
                        Some(c) => TestStatus::Err(format!("Failed (code {c}): {stderr}")),
                        None => TestStatus::Err("Process killed".into()),
                    }
                }
                Err(e) => TestStatus::Err(format!("Spawn failed: {e}")),
            };
            *result.lock().unwrap() = status;
        });
        Ok(())
    }

    fn start_daemon(&mut self) -> anyhow::Result<()> {
        let config_path = self.save_config()?;
        let bin = match self.mode {
            Mode::Server => sibling_binary("union-server"),
            Mode::Client => sibling_binary("union-client"),
        };
        self.daemon.start(&bin, &config_path)?;
        if matches!(self.mode, Mode::Server) {
            self.refresh_fingerprint();
        }
        Ok(())
    }
}

/// Owns the spawned daemon plus a shared log buffer drained by pumper threads.
#[derive(Default)]
struct DaemonHandle {
    inner: Arc<Mutex<Option<RunningDaemon>>>,
    logs: Arc<Mutex<VecDeque<String>>>,
}

struct RunningDaemon {
    child: Child,
    exit: Option<std::process::ExitStatus>,
}

impl DaemonHandle {
    fn is_running(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .as_ref()
            .map(|r| r.exit.is_none())
            .unwrap_or(false)
    }

    fn status_text(&self) -> String {
        let guard = self.inner.lock().unwrap();
        match guard.as_ref() {
            None => "idle".into(),
            Some(r) => match r.exit {
                None => format!("running (pid {})", r.child.id()),
                Some(s) => {
                    if s.success() {
                        "exited (ok)".into()
                    } else {
                        format!("exited (code {:?})", s.code())
                    }
                }
            },
        }
    }

    fn start(&mut self, bin: &Path, config_path: &Path) -> anyhow::Result<()> {
        let mut child = Command::new(bin)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(out) = child.stdout.take() {
            spawn_log_pump_stdout(out, self.logs.clone());
        }
        if let Some(err) = child.stderr.take() {
            spawn_log_pump_stderr(err, self.logs.clone());
        }
        self.logs.lock().unwrap().clear();
        *self.inner.lock().unwrap() = Some(RunningDaemon { child, exit: None });
        Ok(())
    }

    fn reap_if_exited(&mut self) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(r) = guard.as_mut() {
            if r.exit.is_none() {
                if let Ok(Some(status)) = r.child.try_wait() {
                    r.exit = Some(status);
                }
            }
        }
    }

    fn stop(&mut self) {
        if let Some(mut r) = self.inner.lock().unwrap().take() {
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }

    fn snapshot_logs(&self) -> String {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn spawn_log_pump_stdout(stream: ChildStdout, buf: Arc<Mutex<VecDeque<String>>>) {
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            push_log(&buf, line);
        }
    });
}

fn spawn_log_pump_stderr(stream: ChildStderr, buf: Arc<Mutex<VecDeque<String>>>) {
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            push_log(&buf, line);
        }
    });
}

fn push_log(buf: &Arc<Mutex<VecDeque<String>>>, line: String) {
    let mut g = buf.lock().unwrap();
    if g.len() >= LOG_BUFFER_LINES {
        g.pop_front();
    }
    g.push_back(line);
}

fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("UNION_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(target_os = "windows") {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("Union");
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Roaming")
                .join("Union");
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Union");
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("union")
}

fn default_cert_dir() -> PathBuf {
    config_dir().join("certs")
}

fn sibling_binary(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn human_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.2} GiB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2} MiB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.2} KiB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

fn hostname_default() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "this-host".to_string())
    })
}
