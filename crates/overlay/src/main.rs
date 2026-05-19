//! Transparent always-on-top banner.
//!
//! Spawned by the daemons on focus change. The window:
//!  - has no decorations, no taskbar entry on most OSes;
//!  - sits in the top-right corner of the primary display;
//!  - is mouse-passthrough — clicks and motion go through to whatever's
//!    underneath, so the banner can't accidentally steal focus;
//!  - fades in, holds, fades out, then exits.
//!
//! The daemon decides the message; this binary is dumb on purpose.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::time::{Duration, Instant};

use clap::Parser;
use eframe::egui;

const BANNER_W: f32 = 320.0;
const BANNER_H: f32 = 70.0;
const MARGIN: f32 = 24.0;
const FADE_MS: u64 = 150;

#[derive(Parser)]
#[command(name = "union-overlay")]
struct Cli {
    /// Text to show centered in the banner.
    #[arg(long)]
    text: String,
    /// How long to hold at full opacity, in milliseconds. Fade in/out adds
    /// ~150ms on each side.
    #[arg(long, default_value_t = 800)]
    hold_ms: u64,
}

fn main() -> Result<(), eframe::Error> {
    let cli = Cli::parse();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([BANNER_W, BANNER_H])
            .with_decorations(false)
            .with_transparent(true)
            .with_resizable(false)
            .with_always_on_top()
            .with_mouse_passthrough(true)
            // Place near the top-right of the primary display. We don't know
            // the screen size from here; the daemon ideally sends bounds,
            // but a generous offset works in practice on hi-res setups.
            .with_position([1200.0, MARGIN]),
        ..Default::default()
    };
    let total = Duration::from_millis(FADE_MS + cli.hold_ms + FADE_MS);
    let start = Instant::now();
    eframe::run_simple_native("Union overlay", opts, move |ctx, _frame| {
        // Drive repaint until the banner finishes.
        ctx.request_repaint_after(Duration::from_millis(16));

        let elapsed = start.elapsed();
        if elapsed >= total {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let alpha = compute_alpha(elapsed, cli.hold_ms);

        let bg = egui::Color32::from_rgba_unmultiplied(20, 22, 28, (alpha * 220.0) as u8);
        let fg = egui::Color32::from_rgba_unmultiplied(240, 240, 240, (alpha * 255.0) as u8);
        let accent = egui::Color32::from_rgba_unmultiplied(110, 180, 255, (alpha * 255.0) as u8);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(bg)
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(18.0, 14.0)),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("UNION").color(accent).small().strong());
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(&cli.text).color(fg).size(20.0).strong());
                });
            });
    })
}

fn compute_alpha(elapsed: Duration, hold_ms: u64) -> f32 {
    let elapsed_ms = elapsed.as_millis() as u64;
    if elapsed_ms < FADE_MS {
        elapsed_ms as f32 / FADE_MS as f32
    } else if elapsed_ms < FADE_MS + hold_ms {
        1.0
    } else {
        let after = elapsed_ms - FADE_MS - hold_ms;
        (1.0 - after as f32 / FADE_MS as f32).max(0.0)
    }
}
