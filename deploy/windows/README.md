# BAD for Windows: interactive, non-interactive and Intune

Two installers for Windows, same destination, different audiences. Plus an
Intune packaging recipe for the fleet that runs on it.

## Install-BAD-Interactive.ps1 (interactive)

For the human at the keyboard who wants to be asked before anything touches
their machine. It checks prerequisites, asks permission at each step, and
acts only when you say yes:

```powershell
powershell -ExecutionPolicy Bypass -File Install-BAD-Interactive.ps1
```

What it does, in order, each step gated by a yes/no prompt:

1. **Preflight**: confirms Windows and elevation (admin shell)
2. **VC++ Redistributable**: checks for the x64 runtime (numpy and
   scikit-learn need it). Offers to download and install it silently if
   missing. Without it, bad.exe fails to start with the least helpful error
   message Microsoft ever shipped, and that is a high bar.
3. **Service account**: offers to create a local user (no interactive login)
   and add it to Event Log Readers (read the Security log without admin)
4. **Binary**: downloads the release exe (or uses a local artifact for
   offline clients), smoke tests `bad --help`
5. **Config**: drops the example config (never overwrites an existing one),
   validates with `bad check-config`, offers to open the editor
6. **Data directory**: creates the output directory, grants the service
   account full control
7. **Task Scheduler (optional)**: offers to install a daily scheduled task
   for collection, running as the service account. Grants "Log on as a batch
   job" if needed. Fully reversible; the summary prints the removal command.

What it does NOT do: install a service, a driver, or anything that outlives
the script, unless you explicitly say yes to the optional scheduled task. BAD
runs when something runs it. The schedule is your call.

### VC++ Redistributable

This is the one extra dependency Windows might need. PyInstaller bundles the
Python runtime, but numpy and scikit-learn are compiled with MSVC and ship
DLLs that depend on the Visual C++ runtime. A clean Windows box without
VC++ Redistributable x64 will see bad.exe fail to start and nothing else.

The interactive installer checks for it and offers to install it. The
non-interactive installer assumes you handled it. If bad.exe fails to start
on a target machine, install it manually:

```powershell
# Download and install silently
Invoke-WebRequest "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$env:TEMP\vc_redist.x64.exe"
Start-Process "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait
```

## Install-BAD.ps1 (non-interactive)

For fleets, Intune packaging and config management: no questions, same steps
every time, dies on the first surprise.

```powershell
powershell -ExecutionPolicy Bypass -File Install-BAD.ps1 -ServiceAccount BADSVC
```

Parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `-Repo` | GitHub URL | Where release artifacts live |
| `-Version` | `latest` | Pin for a fleet: reproducibility beats novelty |
| `-InstallDir` | `C:\Program Files\BAD` | Where the binary lands |
| `-ConfigDir` | `C:\ProgramData\BAD` | Where the config lands |
| `-ServiceAccount` | (empty) | Account added to Event Log Readers |
| `-ArtifactPath` | (empty) | Local exe for offline clients (Intune bundles) |

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File Uninstall-BAD.ps1 -ServiceAccount BADSVC
```

Deletes the install directory and the config directory. Optionally removes
the account from Event Log Readers. No registry debris, no orphaned service,
because a tool that leaves cleanly the first time is the only kind worth
installing twice.

## Intune (Win32 app)

See `intune/README.md` for the packaging recipe. The short version: bundle
`Install-BAD.ps1`, `Uninstall-BAD.ps1` and the pinned exe, run Microsoft's
Content Prep Tool, upload the `.intunewin`. The interactive installer is not
for Intune (it asks questions); use the non-interactive one for fleet pushes.
