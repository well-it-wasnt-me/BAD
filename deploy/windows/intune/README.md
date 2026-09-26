# BAD for Microsoft Intune (Win32 app)

The same install as `Install-BAD.ps1`, packaged the way Intune likes it: a
Win32 app built with Microsoft's own Content Prep Tool. An `.intunewin` is a
zip of your files with a manifest, and Intune regenerates it per upload, so
no binary lives in this repo. The admin produces it with one command.

Honesty first: this packaging recipe is written to spec and reviewed, but
has not been pushed through a real Intune tenant by this project. Assign it
to one pilot device before the fleet, and watch the first install log.

## 1. Assemble the bundle

Intune extracts the `.intunewin` into a temp folder, so the bundle must be
self-contained: no parent paths, no reaching for GitHub at install time.

Copy into this folder:

- `Install-BAD.ps1` (from `deploy/windows/`)
- `Uninstall-BAD.ps1` (from `deploy/windows/`)
- `bad-windows.exe` (from the
  [releases page](https://github.com/well-it-wasnt-me/BAD/releases), pinned
  to the exact version your fleet runs)

You end up with:

```text
deploy/windows/intune/
    Install-BAD.ps1
    Uninstall-BAD.ps1
    bad-windows.exe
    install.cmd
    uninstall.cmd
    README.md            (this file)
```

## 2. Build the .intunewin

Download the
[Microsoft Win32 Content Prep Tool](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool)
once, then from this folder:

```powershell
IntuneWinAppUtil.exe -c . -s install.cmd -o .
```

That produces `install.intunewin`. One file in, one artifact out, and the
output is reproducible because you pinned the exe version in step 1. Fleets
run pinned versions; only labs run "latest".

## 3. Create the app in Intune

| Intune field | Value |
|---|---|
| App type | Windows app (Win32) |
| Install command | `install.cmd` |
| Uninstall command | `uninstall.cmd` (add `-ServiceAccount BADSVC` to revoke log access) |
| Install behavior | System |
| Detection rule | File exists: `C:\Program Files\BAD\bad.exe` |

Notes worth reading once:

- **Detection**: a file-exists rule on the binary is the whole check. BAD
  installs no service, writes no registry keys and touches nothing in
  `HKLM\Software` for a detector to find, which is a feature, not an
  obstacle.
- **Install behavior**: System context is fine, the installer only writes
  to Program Files and ProgramData. BAD itself still runs unprivileged
  afterwards; the elevation is for the copy, not for the tool.
- **Service account**: `install.cmd` accepts the same arguments as the ps1.
  Add `-ServiceAccount BADSVC` to the install command line and the installer
  grants that account Event Log Readers, which is the boring correct way to
  let `bad collect` read the Security log without an admin.
- **Updates**: bump the pinned exe, rebuild the `.intunewin`, update the app.
  The installer never overwrites an existing `config.toml`, so a fleet update
  does not reset an admin's tuned thresholds. Silent opinion loss is how
  tools get uninstalled out of spite.