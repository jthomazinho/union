//! Minimal egui-based control panel for Union.
//!
//! Lets the user pick Server or Client mode, fill in the relevant fields,
//! and save a TOML config to `~/.config/union/`. Launching the
//! actual daemon as a subprocess and streaming logs into the UI is wired
//! through a child-process supervisor stub — the full integration is
//! tracked as future work.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use eframe::egui;

const APP_TITLE: &str = "Union";

fn main() -> Result<(), eframe::Error> {
    tracing_subscriber::fmt::init();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 480.0])
            .with_title(APP_TITLE),
        ..Default::default()
    };
    eframe::run_native(APP_TITLE, opts, Box::new(|_cc| Ok(Box::new(App::default()))))
}

#[derive(Default)]
struct App {
    mode: Mode,
    server: ServerForm,
    client: ClientForm,
    daemon: Arc<Mutex<Option<Child>>>,
    last_status: String,
}

#[derive(PartialEq, Eq)]
enum Mode {
    Server,
    Client,
}
impl Default for Mode {
    fn default() -> Self {
        Self::Server
    }
}

struct ServerForm {
    port: u16,
    bind: String,
    psk: String,
    clipboard_limit_kb: u64,
}
impl Default for ServerForm {
    fn default() -> Self {
        Self {
            port: protocol::DEFAULT_PORT,
            bind: "0.0.0.0".into(),
            psk: String::new(),
            clipboard_limit_kb: (clipboard_sync::DEFAULT_LIMIT_BYTES / 1024) as u64,
        }
    }
}

struct ClientForm {
    server_addr: String,
    port: u16,
    hostname: String,
    psk: String,
    fingerprint_hex: String,
    clipboard_limit_kb: u64,
}
impl Default for ClientForm {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1".into(),
            port: protocol::DEFAULT_PORT,
            hostname: hostname_default(),
            psk: String::new(),
            fingerprint_hex: String::new(),
            clipboard_limit_kb: (clipboard_sync::DEFAULT_LIMIT_BYTES / 1024) as u64,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("nav").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Union");
                ui.separator();
                ui.radio_value(&mut self.mode, Mode::Server, "Server");
                ui.radio_value(&mut self.mode, Mode::Client, "Client");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.mode {
                Mode::Server => self.draw_server(ui),
                Mode::Client => self.draw_client(ui),
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Save config").clicked() {
                    self.last_status = match self.save_config() {
                        Ok(p) => format!("Saved to {}", p.display()),
                        Err(e) => format!("Save failed: {e}"),
                    };
                }
                let running = self.daemon.lock().unwrap().is_some();
                if !running {
                    if ui.button("Start daemon").clicked() {
                        self.last_status = match self.start_daemon() {
                            Ok(()) => "Daemon started".into(),
                            Err(e) => format!("Start failed: {e}"),
                        };
                    }
                } else if ui.button("Stop daemon").clicked() {
                    self.stop_daemon();
                    self.last_status = "Daemon stopped".into();
                }
            });
            ui.label(&self.last_status);
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
                ui.label("Clipboard limit (KB):");
                ui.add(egui::DragValue::new(&mut self.server.clipboard_limit_kb));
                ui.end_row();
            });
    }

    fn draw_client(&mut self, ui: &mut egui::Ui) {
        ui.label("This machine receives input from the server.");
        ui.add_space(8.0);
        egui::Grid::new("client-grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label("Server address:");
                ui.text_edit_singleline(&mut self.client.server_addr);
                ui.end_row();
                ui.label("Port:");
                ui.add(egui::DragValue::new(&mut self.client.port).range(1..=65535));
                ui.end_row();
                ui.label("Hostname (this machine):");
                ui.text_edit_singleline(&mut self.client.hostname);
                ui.end_row();
                ui.label("Passphrase (PSK):");
                ui.add(egui::TextEdit::singleline(&mut self.client.psk).password(true));
                ui.end_row();
                ui.label("Server fingerprint (hex):");
                ui.text_edit_singleline(&mut self.client.fingerprint_hex);
                ui.end_row();
                ui.label("Clipboard limit (KB):");
                ui.add(egui::DragValue::new(&mut self.client.clipboard_limit_kb));
                ui.end_row();
            });
    }

    fn save_config(&self) -> anyhow::Result<PathBuf> {
        let dir = config_dir();
        std::fs::create_dir_all(&dir)?;
        let (path, toml_text) = match self.mode {
            Mode::Server => (
                dir.join("server.toml"),
                format!(
                    "port = {}\nbind = {:?}\npsk = {:?}\nclipboard_limit_bytes = {}\n",
                    self.server.port,
                    self.server.bind,
                    self.server.psk,
                    self.server.clipboard_limit_kb * 1024,
                ),
            ),
            Mode::Client => (
                dir.join("client.toml"),
                format!(
                    "server_addr = {:?}\nport = {}\nhostname = {:?}\npsk = {:?}\nserver_fingerprint_hex = {:?}\nclipboard_limit_bytes = {}\n",
                    self.client.server_addr,
                    self.client.port,
                    self.client.hostname,
                    self.client.psk,
                    self.client.fingerprint_hex.trim(),
                    self.client.clipboard_limit_kb * 1024,
                ),
            ),
        };
        std::fs::write(&path, toml_text)?;
        Ok(path)
    }

    fn start_daemon(&self) -> anyhow::Result<()> {
        let config_path = self.save_config()?;
        let bin = match self.mode {
            Mode::Server => sibling_binary("union-server"),
            Mode::Client => sibling_binary("union-client"),
        };
        let child = Command::new(&bin)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        *self.daemon.lock().unwrap() = Some(child);
        Ok(())
    }

    fn stop_daemon(&self) {
        if let Some(mut child) = self.daemon.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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
            return PathBuf::from(profile).join("AppData").join("Roaming").join("Union");
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

fn sibling_binary(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
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
