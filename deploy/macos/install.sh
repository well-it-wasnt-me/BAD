#!/bin/zsh
# BAD macOS installer. Mounts the dmg, copies the binary, drops the config,
# verifies. What it does NOT do: install a daemon, a launchd plist, a login
# hook or an input monitor, because BAD runs when something runs it.
#
# Usage:
#   sudo ./install.sh                       # expects bad-macos.dmg next to it
#   sudo DMG=/path/to/bad-macos.dmg ./install.sh
#
# The macOS unified log only opens up for admin-group users, so the account
# that runs `bad collect` should be in the admin group. That is Apple's
# privilege table, not ours.
#
# Read it before you run it. It is shorter than the incident report from not
# reading it.

set -euo pipefail

DMG="${DMG:-bad-macos.dmg}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bad}"

[[ $EUID -eq 0 ]] || { echo "This script writes to $BIN_DIR and $CONFIG_DIR. Run as root (or via sudo)." >&2; exit 1; }
[[ -f "$DMG" ]] || { echo "No dmg at $DMG. Download it from the releases page, or set DMG=/path/to/bad-macos.dmg" >&2; exit 1; }

# --- 1. Mount, copy, unmount --------------------------------------------------

# Mount to a known path so a volume name containing spaces (e.g. "/Volumes/
# BAD 1.2.0") does not break the awk-on-last-field parsing that bit earlier
# versions of this script. A fixed mountpoint means we never parse the path.
mount_point="/tmp/bad-dmg-$$"
hdiutil attach "$DMG" -nobrowse -quiet -mountpoint "$mount_point" >/dev/null 2>&1 \
  || { echo "Could not mount $DMG." >&2; exit 1; }
trap 'hdiutil detach "$mount_point" -quiet >/dev/null 2>&1 || true' EXIT

# The dmg contains the bad executable. Copy, do not run from the mount,
# because running things from a mounted volume is how one-liners become
# postmortems.
[[ -f "$mount_point/bad" ]] || { echo "No bad binary inside the dmg." >&2; exit 1; }

mkdir -p "$BIN_DIR"
cp "$mount_point/bad" "$BIN_DIR/bad"
chmod 0755 "$BIN_DIR/bad"

# --- 2. Config -------------------------------------------------------------------

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    # The example ships inside the dmg too, so the install works offline.
    if [[ -f "$mount_point/config.example.toml" ]]; then
        cp "$mount_point/config.example.toml" "$CONFIG_DIR/config.toml"
    else
        curl -sSfL "https://github.com/well-it-wasnt-me/BAD/raw/main/config.example.toml" \
            -o "$CONFIG_DIR/config.toml"
    fi
    echo "Config template written to $CONFIG_DIR/config.toml (edit it)"
else
    # Never overwrite an existing config. An admin who tuned thresholds does
    # not want a reinstall to reset their opinions.
    echo "Config already exists at $CONFIG_DIR/config.toml, left untouched"
fi

# --- 3. Verify --------------------------------------------------------------------

# The binary and config must prove themselves before we call this an install.
"$BIN_DIR/bad" --help >/dev/null
"$BIN_DIR/bad" check-config --config "$CONFIG_DIR/config.toml"

echo "BAD installed to $BIN_DIR, config at $CONFIG_DIR"
echo "No service was installed, no launchd job was scheduled. BAD runs when you run it."