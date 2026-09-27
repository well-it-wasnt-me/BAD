# BAD for macOS: pkg, MDM and interactive install

For a fleet, a **pkg** is the real answer. Jamf, Microsoft Intune and
Addigy-style MDMs all push a plain macOS installer package, and the same pkg
works for all of them. `install.sh` here is the manual equivalent for one
machine, and `install-interactive.sh` is the guided version for the human at
the keyboard who wants to be asked before anything changes.

Honesty first: these recipes and scripts are written to spec and reviewed,
but have not been run on a real Mac fleet by this project. Mount the dmg on
one sacrificial machine before you trust the recipe with a thousand.

## Interactive installer

```bash
sudo ./install-interactive.sh
# or, if the dmg is not next to the script:
sudo DMG=/path/to/bad-macos.dmg ./install-interactive.sh
```

What it does, in order, each step gated by a yes/no prompt:

1. **Preflight**: confirms macOS, root, and that the dmg exists
2. **Architecture check**: verifies the binary's CPU arch (arm64 / x86_64 /
   universal2) matches the machine. Offers to install Rosetta 2 if an x86_64
   binary landed on Apple Silicon. Aborts if an arm64 binary landed on Intel,
   because Rosetta does not translate in that direction.
3. **Service user**: offers to create a hidden system account and add it to
   the admin group (required for full unified log access, which is Apple's
   privilege table, not ours)
4. **Binary**: mounts the dmg, copies the binary, offers to strip the
   `com.apple.quarantine` attribute (Gatekeeper), smoke tests `bad --help`
5. **Config**: drops the example config (from the dmg or downloaded, never
   overwrites an existing one), validates with `bad check-config`, offers to
   open the editor
6. **Data directory**: creates the output directory, owned by the service user
7. **launchd (optional)**: offers to install a launchd `StartCalendarInterval`
   job for nightly collection. Fully reversible; the summary prints the exact
   removal command

What it does NOT do: install a daemon, a login hook, or an input monitor,
unless you explicitly say yes to the optional launchd job. BAD runs when
something runs it. The schedule is your call.

## Non-interactive installer

```bash
sudo ./install.sh                       # expects bad-macos.dmg next to it
sudo DMG=/path/to/bad-macos.dmg ./install.sh
```

For fleets and scripts: no questions, same steps every time, dies on the
first surprise.

## The pkg recipe

A pkg is a payload plus an identifier. Build one with the stock tools:

```bash
# 1. Assemble the payload exactly as it should land on disk.
#    Standard paths: binary in /usr/local/bin, config in /etc/bad.
mkdir -p payload/usr/local/bin payload/etc/bad
cp bad-macos.dmg-extracted/bad            payload/usr/local/bin/bad
chmod 0755 payload/usr/local/bin/bad
cp config.example.toml                   payload/etc/bad/config.toml

# 2. Wrap it.
VERSION=0.1.0   # match the release tag you built the dmg from
pkgbuild \
    --root payload \
    --identifier com.well-it-wasnt-me.bad \
    --version "$VERSION" \
    --install-location / \
    BAD-"$VERSION".pkg
```

Upload `BAD-<version>.pkg` to your MDM as a macOS installer package, assign
it to your devices, done. MDM installs run as root, so the payload lands
without any of install.sh's sudo ceremony.

Notes worth reading once:

- **The config is a first-run default.** An MDM overwrite policy replaces
  files on redeploy. If your admins tune `config.toml` per machine, prefer a
  separate MDM file-push policy for the config and ship the pkg without
  `/etc/bad`, so an app update never resets an admin's opinions. Silent
  opinion loss is how tools get uninstalled out of spite.
- **The pkg installs no launchd job, no daemon, no login hook.** If you want
  BAD to run on a schedule, push a launchd `StartCalendarInterval` policy
  from the same MDM, like any other policy. The schedule belongs to the
  admin; the math belongs to the tool.
- **Admin group.** The macOS unified log only opens up for admin-group users.
  The account running `bad collect` should be in it. That is Apple's
  privilege table, not ours.
