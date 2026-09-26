# BAD Windows uninstaller. The mirror of Install-BAD.ps1.
#
# What it removes: the binary, the config. What it does NOT remove: your
# collected event data (it does not know where you put it), and the Event Log
# Readers membership if you tell it the account. A tool that leaves cleanly
# the first time is the only kind worth installing twice.
#
# Usage (elevated):
#   powershell -ExecutionPolicy Bypass -File Uninstall-BAD.ps1 -ServiceAccount BADSVC

param(
    [string]$InstallDir = "C:\Program Files\BAD",
    [string]$ConfigDir = "C:\ProgramData\BAD",

    # Pass the account you added at install time to revoke its log access.
    [string]$ServiceAccount = ""
)

$ErrorActionPreference = "Stop"

if ($ServiceAccount -ne "") {
    net localgroup "Event Log Readers" $ServiceAccount /delete
    Write-Host "$ServiceAccount removed from Event Log Readers"
}

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Removed $InstallDir"
}

if (Test-Path $ConfigDir) {
    # Config first, questions later. If you tuned it, it is in your backup.
    Remove-Item -Recurse -Force $ConfigDir
    Write-Host "Removed $ConfigDir"
}

# There is no service, no scheduled task and no registry key left behind,
# because we never made any. Verify for yourself:
Write-Host "BAD uninstalled. No resident components existed to clean up."