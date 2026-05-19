# Windows packaging

Builds `Union-<version>-x86_64.msi` from the workspace via WiX Toolset v3 + `cargo-wix`.

## Prerequisites (one-time)

```powershell
# Rust target for the host
rustup target add x86_64-pc-windows-msvc

# WiX Toolset v3 (candle.exe / light.exe)
choco install wixtoolset      # or: scoop install wixtoolset

# cargo-wix
cargo install cargo-wix
```

## Build

From the repo root, in PowerShell:

```powershell
.\packaging\windows\build.ps1
```

Output: `target\wix\union-gui-<version>-x86_64.msi` (renamed by `cargo-wix` based on the gui crate name).

## Signing

Set `UNION_SIGN_PFX` and `UNION_SIGN_PASSWORD` before invoking `build.ps1` and the script will call `signtool` after WiX produces the `.msi`. Without these, the installer is unsigned and SmartScreen will show a warning until reputation is built.

## Icon

`union.ico` is a generated placeholder. Replace it with a multi-resolution icon (`16x16`, `32x32`, `48x48`, `256x256` PNG-compressed) before shipping public builds.
