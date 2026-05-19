# Build the Union .msi on Windows.
# Requires: WiX Toolset v3 (candle/light on PATH) and cargo-wix.
#   cargo install cargo-wix
#   choco install wixtoolset    (or scoop install wixtoolset)
#
# Optional environment variables:
#   $env:UNION_SIGN_PFX        - path to PFX for signtool
#   $env:UNION_SIGN_PASSWORD   - PFX password
#   $env:UNION_TIMESTAMP_URL   - RFC3161 timestamp URL (default: digicert)
$ErrorActionPreference = "Stop"

$repo = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $repo

if (-not (Get-Command cargo-wix -ErrorAction SilentlyContinue)) {
    Write-Error "cargo-wix not found. Install with: cargo install cargo-wix"
}

Write-Host "==> building release binaries"
cargo build --release `
    --package union-server `
    --package union-client `
    --package union-gui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# cargo-wix expects to drive a single package; we point it at union-gui and pass our
# custom wxs that bundles all three executables.
Write-Host "==> running cargo wix"
# -ext WixFirewallExtension is required for the <fire:FirewallException> elements
# in main.wxs.  Passed to both candle (compile) and light (link).
cargo wix --package union-gui `
    --no-build `
    --nocapture `
    --input "packaging\windows\main.wxs" `
    -C "-ext" -C "WixFirewallExtension" `
    -L "-ext" -L "WixFirewallExtension" `
    -L "-ext" -L "WixUIExtension"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$msi = Get-ChildItem "target\wix\*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $msi) {
    Write-Error "No .msi produced under target\wix\"
}

if ($env:UNION_SIGN_PFX) {
    $ts = if ($env:UNION_TIMESTAMP_URL) { $env:UNION_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
    Write-Host "==> signing $($msi.Name)"
    & signtool sign /fd SHA256 /tr $ts /td SHA256 `
        /f $env:UNION_SIGN_PFX /p $env:UNION_SIGN_PASSWORD `
        $msi.FullName
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "==> UNION_SIGN_PFX unset; .msi is unsigned (SmartScreen will warn)"
}

Write-Host ""
Write-Host "Generated: $($msi.FullName)"
