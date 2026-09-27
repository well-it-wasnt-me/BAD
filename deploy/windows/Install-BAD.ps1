# BAD Windows installer. PowerShell, because .bat is where escaping goes to die.
#
# What it does, in order: downloads the release exe, installs to Program Files,
# drops the config, adds the service account to Event Log Readers, verifies the
# binary runs. What it does NOT do: install a service, a driver, a scheduled
# task, or anything else that outlives this script. BAD runs when you run it.
#
# Usage (elevated, once per machine, ideally through your deployment tool):
#   powershell -ExecutionPolicy Bypass -File Install-BAD.ps1 -ServiceAccount BADSVC
#
# Read it before you run it. It is shorter than the incident report from not
# reading it.

param(
    # GitHub repo the release artifacts live in.
    [string]$Repo = "https://github.com/well-it-wasnt-me/BAD",

    # "latest" resolves to the newest tagged release. Pin a version
    # (e.g. "0.2.0") for a fleet: reproducibility beats novelty.
    [string]$Version = "latest",

    # Standard paths. Change here once, not in five scripts.
    [string]$InstallDir = "C:\Program Files\BAD",
    [string]$ConfigDir = "C:\ProgramData\BAD",

    # The account that will run `bad collect`. Added to Event Log Readers so
    # it can read the Security log WITHOUT being an admin. Leave empty to
    # skip group management entirely.
    [string]$ServiceAccount = "",

    # Path to a bad-windows.exe you already downloaded (Intune Win32 apps
    # bundle it, and clients behind lovely firewalls cannot reach GitHub).
    # Leave empty to download from the release instead.
    [string]$ArtifactPath = ""
)

$ErrorActionPreference = "Stop"

# --- 1. Binary ---------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if ($ArtifactPath -ne "") {
    # Bundled artifact: offline clients get the same binary as everyone else.
    Write-Host "Installing from $ArtifactPath"
    Copy-Item $ArtifactPath "$InstallDir\bad.exe" -Force
} elseif ($Version -eq "latest") {
    $artifact = "$Repo/releases/latest/download/bad-windows.exe"
    Write-Host "Downloading $artifact"
    Invoke-WebRequest -Uri $artifact -OutFile "$InstallDir\bad.exe" -UseBasicParsing
} else {
    $artifact = "$Repo/releases/download/$Version/bad-windows.exe"
    Write-Host "Downloading $artifact"
    Invoke-WebRequest -Uri $artifact -OutFile "$InstallDir\bad.exe" -UseBasicParsing
}

# --- 2. Config ----------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# Never overwrite an existing config. An admin who tuned thresholds does not
# want a reinstall to reset their opinions.
if (-not (Test-Path "$ConfigDir\config.toml")) {
    Invoke-WebRequest -Uri "$Repo/raw/main/config.example.toml" `
        -OutFile "$ConfigDir\config.toml" -UseBasicParsing
    Write-Host "Config template written to $ConfigDir\config.toml (edit it)"
} else {
    Write-Host "Config already exists at $ConfigDir\config.toml, left untouched"
}

# --- 3. Privileges --------------------------------------------------------------

# Event Log Readers is the boring, correct answer for reading the Security
# log. Admin-as-default is how security tools become security findings.
if ($ServiceAccount -ne "") {
    net localgroup "Event Log Readers" $ServiceAccount /add
    Write-Host "$ServiceAccount added to Event Log Readers (collect step only)"
} else {
    Write-Host "No -ServiceAccount given, skipping group membership"
}

# --- 4. Verify ------------------------------------------------------------------

# The binary must prove it runs before we call this an install. A tool that
# cannot pass its own smoke test should fail in the deploy log, not in a
# scheduled task at 3 AM.
& "$InstallDir\bad.exe" --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "bad.exe failed its own --help. The deploy is not done."
}
& "$InstallDir\bad.exe" check-config --config "$ConfigDir\config.toml" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Config failed validation. Edit $ConfigDir\config.toml and retry."
}

Write-Host "BAD installed to $InstallDir, config at $ConfigDir"
Write-Host "No service was installed, no task was scheduled. BAD runs when you run it."