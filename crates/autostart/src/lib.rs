//! Per-user auto-start integration.
//!
//! Each OS gets the most natural per-user mechanism:
//!  - Linux: systemd user unit in `~/.config/systemd/user/`
//!  - macOS: LaunchAgent in `~/Library/LaunchAgents/`
//!  - Windows: a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//!
//! All three install as **user-level** services (no root / no admin), which
//! is what most KVM users actually want.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Install `bin` (with `args`) as a per-user auto-start service identified
/// by `label`. Re-installing overwrites; restarting the active instance is
/// the caller's responsibility on Linux/macOS (the platforms below take
/// care of reload).
pub fn install(label: &str, bin: &Path, args: &[&str]) -> Result<()> {
    let bin = bin
        .canonicalize()
        .with_context(|| format!("resolve {}", bin.display()))?;
    install_impl(label, &bin, args)
}

pub fn uninstall(label: &str) -> Result<()> {
    uninstall_impl(label)
}

// --------- Linux (systemd user) ---------
#[cfg(target_os = "linux")]
fn install_impl(label: &str, bin: &Path, args: &[&str]) -> Result<()> {
    let dir = systemd_user_dir()?;
    std::fs::create_dir_all(&dir)?;
    let unit_path = dir.join(format!("{label}.service"));
    let escaped_args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let exec_start = format!(
        "{} {}",
        shell_quote(bin.to_str().unwrap()),
        escaped_args.join(" ")
    );
    let unit = format!(
        "[Unit]\n\
         Description=Union — {label}\n\
         After=network.target\n\
         \n\
         [Service]\n\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    );
    std::fs::write(&unit_path, unit).with_context(|| format!("write {}", unit_path.display()))?;
    tracing::info!("wrote {}", unit_path.display());
    run("systemctl", &["--user", "daemon-reload"])?;
    run(
        "systemctl",
        &["--user", "enable", "--now", &format!("{label}.service")],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_impl(label: &str) -> Result<()> {
    let unit = format!("{label}.service");
    let _ = run("systemctl", &["--user", "disable", "--now", &unit]);
    let path = systemd_user_dir()?.join(&unit);
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    let _ = run("systemctl", &["--user", "daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_user_dir() -> Result<PathBuf> {
    Ok(xdg_config_home()?.join("systemd").join("user"))
}

#[cfg(target_os = "linux")]
fn xdg_config_home() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = home_dir().context("$HOME unset")?;
    Ok(home.join(".config"))
}

// --------- macOS (launchd) ---------
#[cfg(target_os = "macos")]
fn install_impl(label: &str, bin: &Path, args: &[&str]) -> Result<()> {
    let dir = launch_agents_dir()?;
    std::fs::create_dir_all(&dir)?;
    let plist_path = dir.join(format!("{label}.plist"));
    let mut program_args = String::new();
    program_args.push_str(&format!(
        "        <string>{}</string>\n",
        xml_escape(bin.to_str().unwrap())
    ));
    for a in args {
        program_args.push_str(&format!("        <string>{}</string>\n", xml_escape(a)));
    }
    let log_dir = home_dir()
        .map(|h| h.join("Library").join("Logs").join("Union"))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    std::fs::create_dir_all(&log_dir).ok();
    let stdout = log_dir.join(format!("{label}.out.log"));
    let stderr = log_dir.join(format!("{label}.err.log"));
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key><string>{label}</string>\n\
             <key>ProgramArguments</key>\n    <array>\n{program_args}    </array>\n\
             <key>RunAtLoad</key><true/>\n\
             <key>KeepAlive</key><true/>\n\
             <key>StandardOutPath</key><string>{stdout}</string>\n\
             <key>StandardErrorPath</key><string>{stderr}</string>\n\
         </dict>\n\
         </plist>\n",
        stdout = xml_escape(stdout.to_str().unwrap()),
        stderr = xml_escape(stderr.to_str().unwrap()),
    );
    std::fs::write(&plist_path, plist)
        .with_context(|| format!("write {}", plist_path.display()))?;
    tracing::info!("wrote {}", plist_path.display());
    // Try `bootstrap`; fall back to `load` for older systems. Ignore errors
    // from unload (service may not be loaded yet).
    let _ = run("launchctl", &["unload", plist_path.to_str().unwrap()]);
    if run(
        "launchctl",
        &[
            "bootstrap",
            &format!("gui/{}", unsafe { libc_getuid() }),
            plist_path.to_str().unwrap(),
        ],
    )
    .is_err()
    {
        run("launchctl", &["load", plist_path.to_str().unwrap()])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_impl(label: &str) -> Result<()> {
    let path = launch_agents_dir()?.join(format!("{label}.plist"));
    let _ = run(
        "launchctl",
        &[
            "bootout",
            &format!("gui/{}/{label}", unsafe { libc_getuid() }),
        ],
    );
    let _ = run("launchctl", &["unload", path.to_str().unwrap_or("")]);
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_agents_dir() -> Result<PathBuf> {
    Ok(home_dir()
        .context("$HOME unset")?
        .join("Library")
        .join("LaunchAgents"))
}

#[cfg(target_os = "macos")]
unsafe fn libc_getuid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}

// --------- Windows (HKCU\...\Run) ---------
#[cfg(target_os = "windows")]
fn install_impl(label: &str, bin: &Path, args: &[&str]) -> Result<()> {
    let mut cmdline = String::new();
    cmdline.push('"');
    cmdline.push_str(bin.to_str().context("non-UTF8 path")?);
    cmdline.push('"');
    for a in args {
        cmdline.push(' ');
        cmdline.push('"');
        cmdline.push_str(a);
        cmdline.push('"');
    }
    run(
        "reg",
        &[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            label,
            "/t",
            "REG_SZ",
            "/d",
            &cmdline,
            "/f",
        ],
    )
}

#[cfg(target_os = "windows")]
fn uninstall_impl(label: &str) -> Result<()> {
    let _ = run(
        "reg",
        &[
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            label,
            "/f",
        ],
    );
    Ok(())
}

// --------- shared helpers ---------
fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Some(PathBuf::from(h));
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("USERPROFILE").map(PathBuf::from);
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{cmd} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "_/.-:".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
