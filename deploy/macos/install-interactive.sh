#!/usr/bin/env zsh
# BAD interactive macOS installer.
#
# The non-interactive install.sh is for fleets and MDM: no questions, same
# steps every time. This script is for the human at the keyboard who wants
# to be asked before anything touches their machine. It checks, it asks, it
# acts only with permission, and it says exactly what it did.
#
# Usage:
#   sudo ./install-interactive.sh
#   sudo DMG=/path/to/bad-macos.dmg ./install-interactive.sh
#
# What it does NOT do: install a daemon, a launchd plist, a login hook, or
# an input monitor, unless you explicitly say yes to the optional launchd
# job at the end. BAD runs when something runs it. The schedule is your call.
#
# Read it before you run it. It is shorter than the incident report from not
# reading it, and unlike the incident report, you get to say no at every step.

set -euo pipefail

DMG="${DMG:-bad-macos.dmg}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bad}"
DATA_DIR="${DATA_DIR:-/var/lib/bad}"
SERVICE_USER="${SERVICE_USER:-badsvc}"
LAUNCHD_INSTALL=""

# Colors are nice. Missing terminals are a fact of life. Degrade gracefully.
if [[ -t 1 ]]; then
    C_BOLD=$'\033[1m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_RESET=""
fi

# ---------------------------------------------------------------------------
# Helpers. Small, named, boring. The way helpers should be.
# ---------------------------------------------------------------------------

banner() {
    echo ""
    echo "${C_BOLD}=== $1 ===${C_RESET}"
}

info() {
    echo "${C_GREEN}[ok]${C_RESET}  $1"
}

warn() {
    echo "${C_YELLOW}[warn]${C_RESET} $1"
}

fail() {
    echo "${C_RED}[fail]${C_RESET} $1" >&2
    exit 1
}

ask() {
    # ask "prompt" "default(y|n)" -> echoes "y" or "n".
    local prompt="$1" default="$2" response
    local hint
    if [[ "$default" == "y" ]]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi
    read -r -p "${C_BOLD}${prompt}${C_RESET} ${hint} " response </dev/tty
    response="${response:-$default}"
    case "$response" in
        y|Y|yes|YES) echo "y" ;;
        *) echo "n" ;;
    esac
}

ask_value() {
    # ask_value "prompt" "default" -> echoes the typed value or the default.
    local prompt="$1" default="$2" response
    read -r -p "${C_BOLD}${prompt}${C_RESET} [$default] " response </dev/tty
    echo "${response:-$default}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Step 0: Preflight. Are we even on the right planet?
# ---------------------------------------------------------------------------

preflight() {
    banner "Preflight checks"

    # macOS only. The other platforms have their own installers, and a zsh
    # script that pretends to work on Linux is how support tickets are born.
    if [[ "$(uname -s)" != "Darwin" ]]; then
        fail "This installer is macOS only. You are on $(uname -s). The Linux and Windows installers live in deploy/linux/ and deploy/windows/."
    fi
    info "Operating system: macOS ($(sw_vers -productVersion))"

    # Root is required for writing to /usr/local/bin and /etc. The service
    # user BAD actually runs as is unprivileged; root is just the key to the
    # front door. On macOS, the admin group matters for unified log access,
    # but that is the service user's problem, not the installer's.
    if [[ $EUID -ne 0 ]]; then
        fail "This installer writes to ${BIN_DIR} and ${CONFIG_DIR}. Run as root: sudo ./install-interactive.sh"
    fi
    info "Running as root (install only; BAD itself runs unprivileged)"

    # The dmg must exist. We can mount it, but we cannot download it for you,
    # because Apple's release artifacts come from GitHub, not from us.
    if [[ ! -f "$DMG" ]]; then
        fail "No dmg at $DMG. Download it from the releases page, or set DMG=/path/to/bad-macos.dmg"
    fi
    info "DMG found: $DMG"
}

# ---------------------------------------------------------------------------
# Step 1: Architecture check. The release binary is built on the CI runner's
# native architecture. If the binary is arm64 and this Mac is Intel, it will
# not run. If the binary is x86_64 and this Mac is Apple Silicon, it can run
# via Rosetta 2, but only if Rosetta is installed. Catching this before the
# smoke test saves the admin from the least helpful error in macOS history.
# ---------------------------------------------------------------------------

check_architecture() {
    banner "Architecture compatibility"

    local machine_arch binary_arch
    machine_arch="$(uname -m)"
    info "Machine architecture: $machine_arch"

    # Mount the dmg temporarily to inspect the binary inside it. We detach
    # immediately after, because leaving volumes mounted is how one-liners
    # become postmortems. A fixed mountpoint avoids parsing the volume name,
    # which breaks on dmg names containing spaces.
    local mount_point
    mount_point="/tmp/bad-dmg-$$"
    hdiutil attach "$DMG" -nobrowse -quiet -mountpoint "$mount_point" >/dev/null 2>&1 \
      || fail "Could not mount $DMG."
    trap 'hdiutil detach "$mount_point" -quiet >/dev/null 2>&1 || true' EXIT

    if [[ ! -f "$mount_point/bad" ]]; then
        fail "No bad binary inside the dmg at $DMG."
    fi

    # `lipo -archs` prints the architectures in a universal binary. If the
    # binary is single-arch, it prints just that one. Either way, we check
    # whether the machine's arch is in the list.
    binary_arch=$(lipo -archs "$mount_point/bad" 2>/dev/null || echo "unknown")
    info "Binary architecture: $binary_arch"

    if [[ "$binary_arch" == "unknown" ]]; then
        warn "Could not determine binary architecture via lipo."
        warn "The smoke test at the end will catch a real mismatch."
        return
    fi

    # Universal2 binaries contain both arm64 and x86_64. Nothing to do.
    if [[ "$binary_arch" == *"arm64"* ]] && [[ "$binary_arch" == *"x86_64"* ]]; then
        info "Universal binary: runs on both Apple Silicon and Intel"
        return
    fi

    # Exact match: nothing to do.
    if [[ "$binary_arch" == *"$machine_arch"* ]]; then
        info "Binary matches machine architecture"
        return
    fi

    # arm64 binary on an Intel Mac: dead on arrival. Rosetta does not help
    # here; Rosetta translates x86_64 to arm64, not the other way around.
    if [[ "$binary_arch" == *"arm64"* ]] && [[ "$machine_arch" == "x86_64" ]]; then
        fail "The binary is arm64 (Apple Silicon) but this Mac is Intel. Download the x86_64 or universal build from the releases page."
    fi

    # x86_64 binary on Apple Silicon: needs Rosetta 2. Offer to install it.
    if [[ "$binary_arch" == *"x86_64"* ]] && [[ "$machine_arch" == "arm64" ]]; then
        warn "The binary is x86_64 but this Mac is Apple Silicon."
        warn "It can run via Rosetta 2, but Rosetta must be installed first."

        # Check if Rosetta is already installed.
        if [[ -f "/Library/Apple/usr/share/rosetta/rosetta" ]]; then
            info "Rosetta 2 is already installed"
            return
        fi

        local install_rosetta
        install_rosetta=$(ask "Install Rosetta 2?" "y")
        if [[ "$install_rosetta" == "y" ]]; then
            echo "Installing Rosetta 2..."
            softwareupdate --install-rosetta --agree-to-license
            info "Rosetta 2 installed"
        else
            warn "Skipping Rosetta. The binary will not run without it."
            warn "Install it manually: softwareupdate --install-rosetta --agree-to-license"
            local proceed
            proceed=$(ask "Continue anyway?" "n")
            [[ "$proceed" == "y" ]] || fail "Aborted by user. No changes were made."
        fi
    fi
}

# ---------------------------------------------------------------------------
# Step 2: Service user. The macOS unified log only opens up for admin-group
# users, so the account running collect should be in the admin group. That
# is Apple's privilege table, not ours. We offer to create the account and
# add it, with permission.
# ---------------------------------------------------------------------------

setup_service_user() {
    banner "Service user (reads the unified log)"

    SERVICE_USER=$(ask_value "Service user name" "$SERVICE_USER")

    if id "$SERVICE_USER" >/dev/null 2>&1; then
        info "User '$SERVICE_USER' already exists"
    else
        local create
        create=$(ask "Create user '$SERVICE_USER'?" "y")
        if [[ "$create" == "y" ]]; then
            # A service account with no login shell and no home. On macOS,
            # sysadminctl is the modern way, but it needs a password or
            # interactive confirmation. dscl is the old reliable.
            # We create a hidden system account: UID below 500, no home.
            local max_uid
            max_uid=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1)
            local new_uid=$((max_uid < 500 ? 400 : max_uid + 1))

            dscl . -create "/Users/$SERVICE_USER"
            dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
            dscl . -create "/Users/$SERVICE_USER" UniqueID "$new_uid"
            dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID 20
            dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
            dscl . -create "/Users/$SERVICE_USER" RealName "BAD service account"
            info "User '$SERVICE_USER' created (system account, no login shell)"
        else
            warn "Skipping user creation. Collect will need an account to run as."
            warn "Set SERVICE_USER to an existing account, or create one and re-run."
            return
        fi
    fi

    # The admin group is required for full unified log access. Non-admin
    # users get redacted output, which is less telemetry and more guessing.
    local group
    group=$(ask "Add '$SERVICE_USER' to the admin group (full unified log access)?" "y")
    if [[ "$group" == "y" ]]; then
        dscl . -append "/Groups/admin" GroupMembership "$SERVICE_USER"
        info "'$SERVICE_USER' added to admin group"
    else
        warn "Skipping admin group. Collect will get redacted unified log output."
        warn "That is less telemetry and more guessing. Apple's call, not ours."
    fi
}

# ---------------------------------------------------------------------------
# Step 3: Binary. Mount the dmg, copy the binary, remove the quarantine
# attribute (Gatekeeper), and smoke test it. Running things from a mounted
# volume is how one-liners become postmortems, so we copy first.
# ---------------------------------------------------------------------------

install_binary() {
    banner "BAD binary"

    local bin_path="${BIN_DIR}/bad"

    if [[ -f "$bin_path" ]] && [[ "$(ask "Binary already exists at $bin_path. Overwrite?" "n")" == "n" ]]; then
        info "Keeping existing binary at $bin_path"
        return
    fi

    mkdir -p "$BIN_DIR"

    # Mount, copy, unmount. The trap from check_architecture already detaches,
    # but we do our own mount here in case check_architecture returned early.
    # Fixed mountpoint so a volume name with spaces does not break parsing.
    local mount_point
    mount_point="/tmp/bad-dmg-$$"
    hdiutil attach "$DMG" -nobrowse -quiet -mountpoint "$mount_point" >/dev/null 2>&1 \
      || fail "Could not mount $DMG."
    [[ -f "$mount_point/bad" ]] || { hdiutil detach "$mount_point" -quiet 2>/dev/null || true; fail "No bad binary inside the dmg."; }

    cp "$mount_point/bad" "$bin_path"
    chmod 0755 "$bin_path"
    hdiutil detach "$mount_point" -quiet 2>/dev/null || true

    # Gatekeeper: downloaded binaries carry a com.apple.quarantine extended
    # attribute. Without removing it, the first run shows "cannot be opened
    # because the developer cannot be verified" and the admin has to go
    # click through System Settings > Privacy & Security, which is nobody's
    # idea of a good time. We offer to strip it here.
    if xattr "$bin_path" 2>/dev/null | grep -q "com.apple.quarantine"; then
        warn "Binary has a quarantine attribute (Gatekeeper)."
        warn "Without removing it, macOS will block the first run."
        local strip
        strip=$(ask "Remove quarantine attribute?" "y")
        if [[ "$strip" == "y" ]]; then
            xattr -d com.apple.quarantine "$bin_path" 2>/dev/null || true
            info "Quarantine attribute removed"
        else
            warn "Keeping quarantine. You will need to allow BAD in System Settings > Privacy & Security."
        fi
    fi

    info "Binary installed to $bin_path"

    # The binary must prove it runs before we call this an install. A deploy
    # log entry is a better place to learn the truth than 3 AM.
    if "$bin_path" --help >/dev/null 2>&1; then
        info "Binary smoke test passed (bad --help)"
    else
        fail "Binary failed its own --help. The architecture may be wrong, or Rosetta is needed but not installed."
    fi
}

# ---------------------------------------------------------------------------
# Step 4: Config. Drop the example if none exists. Never overwrite an
# existing config: an admin who tuned thresholds does not want a reinstall
# to reset their opinions. The example may ship inside the dmg, or we fall
# back to downloading it from the repo.
# ---------------------------------------------------------------------------

install_config() {
    banner "Configuration"

    mkdir -p "$CONFIG_DIR"
    local config_path="${CONFIG_DIR}/config.toml"

    if [[ -f "$config_path" ]]; then
        info "Config already exists at $config_path, left untouched"
        local edit
        edit=$(ask "Edit it now with the default editor?" "n")
        if [[ "$edit" == "y" ]]; then
            local editor="${EDITOR:-vi}"
            echo "Opening $config_path with $editor ..."
            $editor "$config_path" </dev/tty >/dev/null 2>&1 || warn "Editor exited with an error. The config is untouched."
        fi
    else
        # Try to extract the example from the dmg first (offline-friendly),
        # then fall back to downloading from the repo. Fixed mountpoint so a
        # volume name with spaces does not break the path.
        local mount_point
        mount_point="/tmp/bad-dmg-cfg-$$"
        if hdiutil attach "$DMG" -nobrowse -quiet -mountpoint "$mount_point" >/dev/null 2>&1; then
            if [[ -f "$mount_point/config.example.toml" ]]; then
                cp "$mount_point/config.example.toml" "$config_path"
            fi
            hdiutil detach "$mount_point" -quiet 2>/dev/null || true
        else
            if command_exists curl; then
                curl -sSfL "https://github.com/well-it-wasnt-me/BAD/raw/main/config.example.toml" -o "$config_path"
            elif command_exists wget; then
                wget -qO "$config_path" "https://github.com/well-it-wasnt-me/BAD/raw/main/config.example.toml"
            else
                warn "No curl/wget and no example in the dmg. Cannot write a config template."
                warn "Create $config_path manually from config.example.toml in the repo."
                return
            fi
        fi
        info "Config template written to $config_path"
        echo "${C_DIM}Edit it to set your SIEM sink, detection thresholds, and input dynamics.${C_RESET}"
        local edit
        edit=$(ask "Edit it now with the default editor?" "y")
        if [[ "$edit" == "y" ]]; then
            local editor="${EDITOR:-vi}"
            echo "Opening $config_path with $editor ..."
            $editor "$config_path" </dev/tty >/dev/null 2>&1 || warn "Editor exited with an error."
        fi
    fi

    # Validate before we declare victory.
    if "${BIN_DIR}/bad" check-config --config "$config_path" >/dev/null 2>&1; then
        info "Config validated successfully"
    else
        warn "Config validation failed. Run: ${BIN_DIR}/bad check-config --config ${config_path}"
        warn "Fix the config and re-run, or BAD will discover the typo at 3 AM instead of you."
    fi
}

# ---------------------------------------------------------------------------
# Step 5: Data directory. Where collect writes its JSONL. Owned by the
# service user, because that is the account that writes to it.
# ---------------------------------------------------------------------------

setup_data_dir() {
    banner "Data directory"

    mkdir -p "$DATA_DIR"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        chown "$SERVICE_USER:admin" "$DATA_DIR"
        info "Data directory $DATA_DIR (owned by $SERVICE_USER)"
    else
        info "Data directory $DATA_DIR (ownership skipped: user '$SERVICE_USER' does not exist)"
    fi
}

# ---------------------------------------------------------------------------
# Step 6 (optional): launchd job. BAD installs no daemon and schedules
# nothing by default. This is the one place the installer offers to bend
# that rule, and only because the admin is standing right here to say yes.
# ---------------------------------------------------------------------------

offer_launchd() {
    banner "Optional: launchd collection job"

    echo "BAD runs when something runs it. A launchd job is one way to make"
    echo "something run it on a cadence. This is optional and fully reversible."
    echo ""

    LAUNCHD_INSTALL=$(ask "Install a launchd job for nightly collection?" "n")
    if [[ "$LAUNCHD_INSTALL" != "y" ]]; then
        info "No launchd job installed. BAD runs when you run it."
        return
    fi

    local hour minute
    hour=$(ask_value "Schedule hour (0-23)" "23")
    minute=$(ask_value "Schedule minute (0-59)" "15")
    local output_path="${DATA_DIR}/events.jsonl"

    local label="com.well-it-wasnt-me.bad-collect"
    local plist_path="/Library/LaunchDaemons/${label}.plist"

    # launchd plists are XML. Apple's format is verbose, but it is the only
    # scheduler macOS ships with, so we write it the way launchd wants it.
    # StartCalendarInterval fires at the given time daily. The job runs,
    # exits, and launchd does not restart it (KeepAlive is false), which is
    # the "tool, not agent" contract in plist form.
    cat > "$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/bad</string>
        <string>collect</string>
        <string>--platform</string>
        <string>macos</string>
        <string>--output</string>
        <string>${output_path}</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>${hour}</integer>
        <key>Minute</key>
        <integer>${minute}</integer>
    </dict>
    <key>KeepAlive</key>
    <false/>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
PLIST

    chmod 0644 "$plist_path"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        chown "root:admin" "$plist_path"
    fi

    launchctl load -w "$plist_path" 2>/dev/null \
        && info "launchd job installed: $label (daily at ${hour}:${minute})" \
        || warn "Could not load launchd job. Run: launchctl load -w $plist_path"

    echo "${C_DIM}Remove later: launchctl unload -w $plist_path && rm $plist_path${C_RESET}"
}

# ---------------------------------------------------------------------------
# Step 7: Summary. What we did, what we did not, and what to do next.
# ---------------------------------------------------------------------------

summary() {
    banner "Installation summary"

    echo "  Binary:    ${BIN_DIR}/bad"
    echo "  Config:    ${CONFIG_DIR}/config.toml"
    echo "  Data dir:  ${DATA_DIR}"
    echo "  Service:   ${SERVICE_USER}"
    if [[ "$LAUNCHD_INSTALL" == "y" ]]; then
        echo "  Schedule:  launchd com.well-it-wasnt-me.bad-collect (installed)"
    else
        echo "  Schedule:  none (BAD runs when you run it)"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. ${BIN_DIR}/bad check-config --config ${CONFIG_DIR}/config.toml"
    echo "  2. sudo -u ${SERVICE_USER} ${BIN_DIR}/bad collect --platform macos --output ${DATA_DIR}/events.jsonl"
    echo "  3. ${BIN_DIR}/bad train --input ${DATA_DIR}/events.jsonl --output ${DATA_DIR}/model.joblib"
    echo ""
    echo "No daemon was installed. No launchd job lingers (unless you said yes)."
    echo "BAD runs when you run it, and stops when it is done, which is the"
    echo "only kind of tool worth running twice."
}

# ---------------------------------------------------------------------------
# Main: steps in order, each one honest about what it is about to do.
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo "${C_BOLD}BAD: Behavior Anomaly Detection - interactive macOS installer${C_RESET}"
    echo "${C_DIM}You will be asked before anything changes. Say no to anything you do not like.${C_RESET}"

    preflight
    check_architecture
    setup_service_user
    install_binary
    install_config
    setup_data_dir
    offer_launchd
    summary
}

main "$@"
