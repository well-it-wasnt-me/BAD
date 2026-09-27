# Fleet deployment for IT and sysadmins

BAD ships no daemon, no service, no watchdog and no input hooks. It runs when
something runs it, and then it stops. That is the "tool, not agent" contract:
the binary does math and leaves. If you want that math to happen every night,
you own the schedule, and that is exactly how it should be. Convenience that
requires a resident process is how tools turn into liability.

What follows is the whole ceremony: prerequisites, install, verify on one
pilot machine, then push to the fleet with the templates in `deploy/`.

## 1. Prerequisites per platform

Install everything **unprivileged**. BAD never wants root, and a security
tool that demands it should raise an eyebrow.

| Platform | Run as | Privilege needed | What it buys |
|---|---|---|---|
| Linux | Any user, in the `systemd-journal` group | Group membership only | `journalctl` access for `bad collect` |
| Linux | Same | `auditd` enabled system-wide (root once, at provisioning) | Process exec and shell command telemetry |
| Windows | Any service account, in `Event Log Readers` | Group membership, on the collect step only | `Get-WinEvent` access to the Security log |
| Windows | Without the group: admin | Only for `bad collect`, run from an elevated shell | Same telemetry, worse hygiene |
| macOS | Any admin-group user | Admin group, for the full unified log | `log show` beyond the default privacy redactions |

Notes that save an afternoon:

- On Linux, add the collection user to the group once:
  `sudo usermod -aG systemd-journal badsvc`, then relogin. Running collect
  with `sudo` works too, but sudo in a schedule is a habit worth breaking.
- On Windows, `Event Log Readers` is the correct, boring answer:
  `net localgroup "Event Log Readers" BADSVC /add`. Admin-as-default is how
  collections of security tools become security findings.
- On macOS, non-admin users get redacted unified log output. The admin
  group gets the full firehose. Pick your tradeoff and write it down.

Runtime dependencies worth knowing:

- **Windows**: the PyInstaller binary bundles Python, numpy and scikit-learn,
  but numpy and scikit-learn are compiled with MSVC and depend on the
  Visual C++ Redistributable x64 runtime. A clean Windows box without it will
  see bad.exe fail to start and nothing else. The interactive installer
  (`Install-BAD-Interactive.ps1`) checks for it and offers to install it. For
  fleet pushes, install it once via your config management or Intune:
  download `vc_redist.x64.exe` from
  `https://aka.ms/vs/17/release/vc_redist.x64.exe` and run it with
  `/install /quiet /norestart`.
- **macOS**: the release binary is built on the CI runner's native
  architecture. If the binary is arm64 and the target Mac is Intel, it will
  not run (Rosetta does not translate in that direction). If the binary is
  x86_64 and the target Mac is Apple Silicon, it runs via Rosetta 2, which
  must be installed first (`softwareupdate --install-rosetta
  --agree-to-license`). The interactive installer (`install-interactive.sh`)
  checks this and offers to install Rosetta. Downloaded binaries also carry a
  `com.apple.quarantine` attribute (Gatekeeper); the interactive installer
  offers to strip it, or the admin allows BAD in System Settings > Privacy &
  Security. Universal2 builds (arm64 + x86_64) avoid both issues.

And to state the part worth repeating on a fleet page: BAD never hooks the
keyboard or mouse, never captures keystroke content, and no configuration
option enables that on any platform, ever. Input dynamics arrive as timing
and motion aggregates from an agent you already trust, or not at all.

## 2. Install the binary

Grab the artifact for your OS from the
[releases page](https://github.com/well-it-wasnt-me/BAD/releases), drop the
binary in the standard place, and give it a config:

| Platform | Binary | Standard path | Config file |
|---|---|---|---|
| Linux | `bad-linux` | `/usr/local/bin/bad` or `/opt/bad/bad` | `/etc/bad/config.toml` |
| Windows | `bad-windows.exe` | `C:\Program Files\BAD\bad.exe` | `C:\ProgramData\BAD\config.toml` |
| macOS | `bad-macos.dmg` | `/usr/local/bin/bad` (from the dmg) | `/etc/bad/config.toml` |

Copy `config.example.toml` from the repo to the config path, edit it, and
validate it:

```bash
bad check-config --config /etc/bad/config.toml
```

Every key is optional, so a one-line config is a working config. The example
file documents every toggle and the precedence: flags beat the file, the file
beats the defaults.

## 3. Verify on one pilot machine

Before anything touches a second machine, prove the first one:

```bash
bad --help                                              # binary runs, PATH is sane
bad check-config --config /etc/bad/config.toml          # config parses and validates
bad collect --platform linux --output /tmp/pilot.jsonl  # telemetry actually flows
bad train --input /tmp/pilot.jsonl --output /tmp/pilot.joblib
```

Training on a fresh machine will be thin, and that is fine: this is a smoke
test, not a baseline. You are proving the pipes hold pressure, and collecting
the first events of the baseline you will actually use. See
[Testing and Baselines](testing.md) for how long the real thing takes.
Admins forgive tools that verify themselves before spreading. Tools that
skip that step get uninstalled during the incident, along with whoever
pushed them.

## 4. Push to the fleet

The repo ships deployment templates in `deploy/`, one per ecosystem. They are
small on purpose: read them before you run them, they are shorter than the
incident report from not reading them.

One thing said plainly: the templates are written to spec and reviewed, but
they have not been executed on real Windows, ansible-managed or macOS fleets
by this project. They are starting points, not blessed artifacts. Dry run on
a sacrificial machine first (the `--check --diff` note in the ansible README,
a single pilot box for the rest), and treat the first fleet-wide push as the
moment the templates graduate from "reviewed" to "tested". Admins forgive
tools that verify themselves before spreading; the templates extend the same
courtesy to you.

| Ecosystem | Template | What it does |
|---|---|---|
| Windows, manual | `deploy/windows/Install-BAD.ps1` | Downloads the release exe, installs to Program Files, drops the config, adds the service account to Event Log Readers |
| Windows, interactive | `deploy/windows/Install-BAD-Interactive.ps1` | Checks for VC++ Redistributable, asks permission at each step, installs the binary and config, optionally sets up a Task Scheduler job. For the human at the keyboard |
| Windows, Intune | `deploy/windows/intune/` | The same steps as `install.cmd`/`uninstall.cmd` for Win32 app packaging, with the exact build command |
| Linux, Ansible | `deploy/linux/ansible/` | A small role: group membership, config template, binary install, config validation handler |
| Linux, no fleet tool | `deploy/linux/install.sh` | The same steps as a plain shell script, for shops where Ansible is a rumor |
| Linux, interactive | `deploy/linux/install-interactive.sh` | Checks prerequisites, asks permission at each step, installs auditd and the binary, optionally sets up a systemd timer. For the human at the keyboard |
| macOS, MDM | `deploy/macos/` | `install.sh` from the dmg, plus the pkg build recipe that Jamf, Intune and Addigy can all push |
| macOS, interactive | `deploy/macos/install-interactive.sh` | Checks architecture (arm64/x86_64, offers Rosetta 2), strips Gatekeeper quarantine, asks permission at each step, optionally sets up a launchd job. For the human at the keyboard |

## 5. Running on a schedule

Nothing about BAD requires a schedule, but a baseline does not build itself.
Pick your OS's native scheduler and run collect/train on whatever cadence
your storage can stomach; nightly is a sane start.

A Linux systemd **timer** (not a service, the unit runs and exits, which is
the point):

```ini
# /etc/systemd/system/bad-collect.service
[Unit]
Description=BAD behavior collection (runs, exits, leaves nobody behind)

[Service]
User=badsvc
ExecStart=/usr/local/bin/bad collect --platform linux \
    --output /var/lib/bad/events.jsonl
```

```ini
# /etc/systemd/system/bad-collect.timer
[Unit]
Description=Run BAD collection nightly

[Timer]
OnCalendar=*-*-* 23:15:00
Persistent=true

[Install]
WantedBy=timers.target
```

On Windows, Task Scheduler with the service account, daily, running the same
`bad collect` line. On macOS, a launchd `StartCalendarInterval` plist doing
the same, or push the schedule from your MDM like any other policy.

The pattern everywhere is identical: a scheduler you already trust runs an
unprivileged binary on a cadence you already chose. BAD brings the math,
your platform brings the calendar.

## 6. Uninstall

Delete the install directory, the config directory, and the collection data
you pointed it at. Optionally remove the account from the journal or Event
Log Readers group. There is no registry debris, no orphaned service, no
phone-home, and no uninstaller needed beyond `rm`, because a tool that
leaves cleanly the first time is the only kind worth installing twice.