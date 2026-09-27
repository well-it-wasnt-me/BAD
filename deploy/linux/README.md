# BAD Linux installers

Two installers for Linux, same destination, different audiences.

## install.sh (non-interactive)

For fleets and config management. No questions, same steps every time, dies on
the first surprise. Set environment variables to override defaults:

```bash
sudo BAD_VERSION=latest SERVICE_USER=badsvc ./install.sh
```

See the header of `install.sh` for every override. Ansible shops should use
the role in `ansible/` instead; this script is for shops where Ansible is a
rumor.

## install-interactive.sh (interactive)

For the human at the keyboard who wants to be asked before anything touches
their machine. It checks prerequisites, asks permission at each step, and
acts only when you say yes:

```bash
sudo ./install-interactive.sh
```

What it does, in order, each step gated by a yes/no prompt:

1. **Preflight**: confirms Linux, root, and a download tool (curl or wget)
2. **Package manager**: detects apt/dnf/yum/pacman/zypper for dependency installs
3. **systemd journal**: checks for `journalctl` (the Linux collector's data source)
4. **auditd**: offers to install and enable it (process exec and shell command
   telemetry, the good stuff)
5. **Service user**: offers to create an unprivileged system account and add it
   to the `systemd-journal` group (collect without root)
6. **Binary**: downloads the release artifact, with a smoke test (`bad --help`)
7. **Config**: drops the example config (never overwrites an existing one),
   validates it with `bad check-config`
8. **Data directory**: creates the output directory, owned by the service user
9. **Timer (optional)**: offers to install a systemd timer for nightly
   collection. Fully reversible; the summary prints the exact removal command

What it does NOT do: install a daemon, a service, or anything that outlives
the script, unless you explicitly say yes to the optional timer. BAD runs when
something runs it. The schedule is your call.

Read it before you run it. It is shorter than the incident report from not
reading it, and unlike the incident report, you get to say no at every step.
