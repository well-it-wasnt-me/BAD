# BAD for macOS: pkg and MDM

For a fleet, a **pkg** is the real answer. Jamf, Microsoft Intune and
Addigy-style MDMs all push a plain macOS installer package, and the same pkg
works for all of them. `install.sh` here is the manual equivalent for one
machine, and it is also the reference for what the pkg must do: copy a binary,
drop a config, verify, leave.

Honesty first: this recipe and `install.sh` are written to spec and reviewed,
but have not been run on a real Mac fleet by this project. Mount the dmg on
one sacrificial machine before you trust the recipe with a thousand.

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

## Manual install from the dmg

```bash
hdiutil attach bad-macos.dmg
sudo installer -pkg /Volumes/BAD/BAD.pkg -target /    # if the dmg carries a pkg
# or, for a dmg with a plain binary:
sudo ./install.sh                                    # same steps, no MDM
```

Either way, verify before you believe it:

```bash
bad --help
bad check-config --config /etc/bad/config.toml
```