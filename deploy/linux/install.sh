#!/usr/bin/env bash
# BAD Linux installer. The ansible role without ansible: same steps, same
# order, same refusal to install anything that outlives this script.
#
# Usage (as root, once per machine, or through your config management):
#   sudo ./install.sh
#
# Environment overrides, for the fleet that does not fit the defaults:
#   BAD_VERSION=latest          pin like BAD_VERSION=0.2.0 for a fleet
#   BIN_DIR=/usr/local/bin      where the binary lands
#   CONFIG_DIR=/etc/bad         where the config lands
#   DATA_DIR=/var/lib/bad       where you point --output
#   SERVICE_USER=badsvc         the unprivileged account that runs collect
#   REPO_URL=https://github.com/well-it-wasnt-me/BAD
#
# Read it before you run it. It is shorter than the incident report from not
# reading it.

set -euo pipefail

BAD_VERSION="${BAD_VERSION:-latest}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bad}"
DATA_DIR="${DATA_DIR:-/var/lib/bad}"
SERVICE_USER="${SERVICE_USER:-badsvc}"
REPO_URL="${REPO_URL:-https://github.com/well-it-wasnt-me/BAD}"

[[ $EUID -eq 0 ]] || { echo "This script writes to $BIN_DIR and $CONFIG_DIR. Run as root." >&2; exit 1; }

# --- 1. Resolve the artifact -------------------------------------------------

if [[ "$BAD_VERSION" == "latest" ]]; then
    # Follow the redirect and read the tag out of it. Fleets should pin
    # BAD_VERSION instead; "latest" is for pilots and optimists.
    redirect=$(curl -sS -o /dev/null -w '%{redirect_url}' "$REPO_URL/releases/latest")
    BAD_VERSION=${redirect##*tag/}
fi
artifact="$REPO_URL/releases/download/$BAD_VERSION/bad-linux"

# --- 2. Binary ----------------------------------------------------------------

echo "Downloading $artifact"
curl -sSfL "$artifact" -o "$BIN_DIR/bad"
chmod 0755 "$BIN_DIR/bad"

# --- 3. Config ----------------------------------------------------------------

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
    curl -sSfL "$REPO_URL/raw/main/config.example.toml" -o "$CONFIG_DIR/config.toml"
    echo "Config template written to $CONFIG_DIR/config.toml (edit it)"
else
    # Never overwrite an existing config. An admin who tuned thresholds does
    # not want a reinstall to reset their opinions.
    echo "Config already exists at $CONFIG_DIR/config.toml, left untouched"
fi

# --- 4. Privileges --------------------------------------------------------------

# Group membership is the boring, correct privilege. sudo in a schedule is
# a habit worth breaking.
if id "$SERVICE_USER" >/dev/null 2>&1; then
    usermod -aG systemd-journal "$SERVICE_USER"
    echo "$SERVICE_USER added to systemd-journal (collect without root)"
else
    echo "User $SERVICE_USER does not exist; create it or set SERVICE_USER." >&2
    echo "Skipping group membership for now. Nothing is broken, but collect will be." >&2
fi

mkdir -p "$DATA_DIR"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    chown "$SERVICE_USER:" "$DATA_DIR"
fi

# --- 5. Verify -------------------------------------------------------------------

# The binary and config must prove themselves before we call this an install.
# A deploy log entry is a better place to learn the truth than 3 AM.
"$BIN_DIR/bad" --help >/dev/null
"$BIN_DIR/bad" check-config --config "$CONFIG_DIR/config.toml"

echo "BAD $BAD_VERSION installed to $BIN_DIR, config at $CONFIG_DIR"
echo "No service was installed, no timer was scheduled. BAD runs when you run it."