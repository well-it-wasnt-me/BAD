#!/usr/bin/env bash
# BAD interactive Linux installer.
#
# The non-interactive install.sh is for fleets and config management: no
# questions, same steps every time, die on the first surprise. This script
# is for the human at the keyboard who wants to be asked before anything
# touches their machine. It checks, it asks, it acts only with permission,
# and it says exactly what it did. The opposite of a daemon, in script form.
#
# Usage:
#   sudo ./install-interactive.sh
#
# What it does NOT do: install a service, a daemon, or anything that outlives
# the script, unless you explicitly say yes to the optional systemd timer at
# the end. BAD runs when something runs it. The schedule is your call.
#
# Read it before you run it. It is shorter than the incident report from not
# reading it, and unlike the incident report, you get to say no at every step.

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals, with defaults an admin can override at the prompts.
# ---------------------------------------------------------------------------
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bad}"
DATA_DIR="${DATA_DIR:-/var/lib/bad}"
SERVICE_USER="${SERVICE_USER:-badsvc}"
REPO_URL="${REPO_URL:-https://github.com/well-it-wasnt-me/BAD}"
BAD_VERSION="${BAD_VERSION:-latest}"
TIMER_INSTALL=""

# Colors are nice. Missing terminals are a fact of life. Degrade gracefully.
if [[ -t 1 ]]; then
    C_BOLD=$'\033[1m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_RESET=""
fi

# ---------------------------------------------------------------------------
# Helpers. Small, named, and boring. The way helpers should be.
# ---------------------------------------------------------------------------

banner() {
    # A section header. If this script had a theme song, this is where it played.
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
    # Empty input takes the default, because decisions are hard enough
    # without making the default a guessing game.
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
# Step 0: Are we even on the right planet?
# ---------------------------------------------------------------------------

preflight() {
    banner "Preflight checks"

    # Linux only. The other platforms have their own installers, and a bash
    # script that pretends to work on macOS is how support tickets are born.
    if [[ "$(uname -s)" != "Linux" ]]; then
        fail "This installer is Linux only. You are on $(uname -s). The Windows and macOS installers live in deploy/windows/ and deploy/macos/."
    fi
    info "Operating system: Linux ($(uname -r))"

    # Root is not a personality, it is a requirement for writing to /usr/local
    # and /etc. The service user BAD actually runs as is unprivileged; root
    # is just the key to the front door.
    if [[ $EUID -ne 0 ]]; then
        fail "This installer writes to ${BIN_DIR} and ${CONFIG_DIR}. Run as root: sudo ./install-interactive.sh"
    fi
    info "Running as root (install only; BAD itself runs unprivileged)"

    # A shell without curl or wget cannot download the binary. We could ship
    # one inside the script, but that is how trust dies.
    if ! command_exists curl && ! command_exists wget; then
        fail "Neither curl nor wget found. Install one and come back."
    fi
    info "Download tool present"
}

# ---------------------------------------------------------------------------
# Step 1: Detect the package manager. This decides how we install auditd
# and friends, if the admin says yes. Package managers are like opinions:
# every distro has one, and none of them agree on the flag syntax.
# ---------------------------------------------------------------------------

detect_package_manager() {
    PKG_MANAGER=""
    PKG_INSTALL_CMD=""

    if command_exists apt-get; then
        PKG_MANAGER="apt-get"
        PKG_INSTALL_CMD="apt-get install -y"
    elif command_exists dnf; then
        PKG_MANAGER="dnf"
        PKG_INSTALL_CMD="dnf install -y"
    elif command_exists yum; then
        PKG_MANAGER="yum"
        PKG_INSTALL_CMD="yum install -y"
    elif command_exists pacman; then
        PKG_MANAGER="pacman"
        PKG_INSTALL_CMD="pacman -S --noconfirm"
    elif command_exists zypper; then
        PKG_MANAGER="zypper"
        PKG_INSTALL_CMD="zypper install -y"
    fi

    if [[ -z "$PKG_MANAGER" ]]; then
        warn "No supported package manager found (apt/dnf/yum/pacman/zypper)."
        warn "Dependency installation steps will be skipped. Install auditd manually if you want it."
    else
        info "Package manager: $PKG_MANAGER"
    fi
}

# ---------------------------------------------------------------------------
# Step 2: systemd journal. The Linux collector reads journalctl, so no
# journal means no collect. We cannot install systemd for you; that is a
# lifestyle choice that predates this script.
# ---------------------------------------------------------------------------

check_journal() {
    banner "Systemd journal (the Linux collector's data source)"

    if command_exists journalctl; then
        info "journalctl found on PATH"
    else
        warn "journalctl not found. The Linux collector will not work without it."
        warn "This box does not run systemd, or systemd is not on PATH."
        warn "If your box uses a different init system, feed BAD events via the jsonl collector instead."
        local proceed
        proceed=$(ask "Continue anyway (the jsonl collector still works)?" "n")
        [[ "$proceed" == "y" ]] || fail "Aborted by user. No changes were made."
    fi
}

# ---------------------------------------------------------------------------
# Step 3: auditd. The good telemetry (process exec, shell commands) comes
# from auditd records relayed through journald. Without it, collect only
# sees sshd and sudo entries, which is thin gruel. We offer to install and
# enable it, with permission, because nobody likes a script that installs
# kernel-level audit frameworks as a surprise.
# ---------------------------------------------------------------------------

check_auditd() {
    banner "auditd (process exec and shell command telemetry)"

    if command_exists auditd || command_exists augenrules; then
        info "auditd is already installed"
    else
        warn "auditd not found. Without it, collect only sees sshd and sudo."
        warn "Process exec and shell command telemetry require auditd."
        local install
        install=$(ask "Install auditd?" "y")
        if [[ "$install" == "y" ]]; then
            if [[ -z "$PKG_MANAGER" ]]; then
                fail "Cannot install auditd: no supported package manager. Install it manually and re-run."
            fi
            echo "Installing auditd via $PKG_MANAGER..."
            $PKG_INSTALL_CMD audit auditd 2>/dev/null || $PKG_INSTALL_CMD audit 2>/dev/null || {
                warn "Package install did not find an audit package by that name."
                warn "Some distros call it 'audit', others 'auditd'. Check your distro and install manually."
            }
            command_exists auditd && info "auditd installed" || warn "auditd install may have used a different package name. Verify manually."
        else
            warn "Skipping auditd. Collect will only see sshd and sudo entries."
        fi
    fi

    # Enable and start auditd if it is present and systemd manages it.
    if command_exists auditd && command_exists systemctl; then
        local enable
        enable=$(ask "Enable and start auditd at boot?" "y")
        if [[ "$enable" == "y" ]]; then
            systemctl enable --now auditd 2>/dev/null && info "auditd enabled and started" \
                || warn "Could not enable auditd via systemctl. It may be managed differently on this distro."
        fi
    fi
}

# ---------------------------------------------------------------------------
# Step 4: Service user. BAD never wants root. The account that runs collect
# gets a boring group membership (systemd-journal) and ownership of the data
# directory, and that is the entire privilege story. We offer to create it.
# ---------------------------------------------------------------------------

setup_service_user() {
    banner "Service user (the unprivileged account that runs collect)"

    SERVICE_USER=$(ask_value "Service user name" "$SERVICE_USER")

    if id "$SERVICE_USER" >/dev/null 2>&1; then
        info "User '$SERVICE_USER' already exists"
    else
        local create
        create=$(ask "Create user '$SERVICE_USER'?" "y")
        if [[ "$create" == "y" ]]; then
            # --system is the polite way: no login shell, no home, no password.
            # A service account that can log in interactively is an attack
            # surface wearing a name tag.
            useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
                || useradd -r -M -s /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
                || fail "Could not create user '$SERVICE_USER'. Create it manually and re-run."
            info "User '$SERVICE_USER' created (system account, no login shell)"
        else
            warn "Skipping user creation. Collect will need an account to run as."
            warn "Set SERVICE_USER to an existing account, or create one and re-run."
            return
        fi
    fi

    # Group membership is the boring, correct privilege. sudo in a schedule
    # is a habit worth breaking, and so is sudo in an install script.
    if command_exists journalctl; then
        local group
        group=$(ask "Add '$SERVICE_USER' to the systemd-journal group (collect without root)?" "y")
        if [[ "$group" == "y" ]]; then
            usermod -aG systemd-journal "$SERVICE_USER"
            info "'$SERVICE_USER' added to systemd-journal"
        else
            warn "Skipping group membership. Collect will need sudo or root to read the journal."
        fi
    fi
}

# ---------------------------------------------------------------------------
# Step 5: Binary. Download the release artifact, or skip if the admin
# already dropped one in place. Fleets should pin a version; "latest" is
# for pilots and optimists.
# ---------------------------------------------------------------------------

install_binary() {
    banner "BAD binary"

    BAD_VERSION=$(ask_value "Version (or 'latest')" "$BAD_VERSION")
    local bin_path="${BIN_DIR}/bad"

    if [[ -f "$bin_path" ]] && [[ "$(ask "Binary already exists at $bin_path. Overwrite?" "n")" == "n" ]]; then
        info "Keeping existing binary at $bin_path"
        return
    fi

    local artifact
    if [[ "$BAD_VERSION" == "latest" ]]; then
        artifact="$REPO_URL/releases/latest/download/bad-linux"
    else
        artifact="$REPO_URL/releases/download/$BAD_VERSION/bad-linux"
    fi

    echo "Downloading $artifact ..."
    if command_exists curl; then
        curl -sSfL "$artifact" -o "$bin_path"
    else
        wget -qO "$bin_path" "$artifact"
    fi
    chmod 0755 "$bin_path"
    info "Binary installed to $bin_path"

    # The binary must prove it runs before we call this an install.
    # A deploy log entry is a better place to learn the truth than 3 AM.
    if "$bin_path" --help >/dev/null 2>&1; then
        info "Binary smoke test passed (bad --help)"
    else
        fail "Binary failed its own --help. The download may be corrupt or the architecture wrong."
    fi
}

# ---------------------------------------------------------------------------
# Step 6: Config. Drop the example if none exists. Never overwrite an
# existing config: an admin who tuned thresholds does not want a reinstall
# to reset their opinions.
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
        echo "Downloading config template to $config_path ..."
        if command_exists curl; then
            curl -sSfL "$REPO_URL/raw/main/config.example.toml" -o "$config_path"
        else
            wget -qO "$config_path" "$REPO_URL/raw/main/config.example.toml"
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

    # Validate before we declare victory. The same command the deployment
    # templates run, so what this log said is what the fleet will do.
    if "${BIN_DIR}/bad" check-config --config "$config_path" >/dev/null 2>&1; then
        info "Config validated successfully"
    else
        warn "Config validation failed. Run: ${BIN_DIR}/bad check-config --config ${config_path}"
        warn "Fix the config and re-run, or BAD will discover the typo at 3 AM instead of you."
    fi
}

# ---------------------------------------------------------------------------
# Step 7: Data directory. Where collect writes its JSONL. Owned by the
# service user, because that is the account that writes to it.
# ---------------------------------------------------------------------------

setup_data_dir() {
    banner "Data directory"

    mkdir -p "$DATA_DIR"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        chown "$SERVICE_USER:" "$DATA_DIR"
        info "Data directory $DATA_DIR (owned by $SERVICE_USER)"
    else
        info "Data directory $DATA_DIR (ownership skipped: user '$SERVICE_USER' does not exist)"
    fi
}

# ---------------------------------------------------------------------------
# Step 8 (optional): systemd timer. BAD installs no service and schedules
# nothing by default. This is the one place the installer offers to bend
# that rule, and only because the admin is standing right here to say yes.
# ---------------------------------------------------------------------------

offer_timer() {
    banner "Optional: systemd collection timer"

    echo "BAD runs when something runs it. A systemd timer is one way to make"
    echo "something run it on a cadence. This is optional and fully reversible."
    echo ""

    if ! command_exists systemctl; then
        warn "systemctl not found. Skipping timer setup; use your platform's scheduler."
        return
    fi

    TIMER_INSTALL=$(ask "Install a systemd timer for nightly collection?" "n")
    if [[ "$TIMER_INSTALL" != "y" ]]; then
        info "No timer installed. BAD runs when you run it."
        return
    fi

    local schedule
    schedule=$(ask_value "Timer schedule (systemd OnCalendar, e.g. '*-*-* 23:15:00')" "*-*-* 23:15:00")
    local output_path="${DATA_DIR}/events.jsonl"

    # The service unit: runs, exits, leaves nobody behind. No daemon, no
    # restart, no lingering process. The timer fires it, it does its math,
    # it goes home.
    local service_unit="/etc/systemd/system/bad-collect.service"
    cat > "$service_unit" <<UNIT
[Unit]
Description=BAD behavior collection (runs, exits, leaves nobody behind)

[Service]
User=${SERVICE_USER}
ExecStart=${BIN_DIR}/bad collect --platform linux --output ${output_path}
UNIT

    local timer_unit="/etc/systemd/system/bad-collect.timer"
    cat > "$timer_unit" <<UNIT
[Unit]
Description=Run BAD collection on a schedule

[Timer]
OnCalendar=${schedule}
Persistent=true

[Install]
WantedBy=timers.target
UNIT

    systemctl daemon-reload
    systemctl enable --now bad-collect.timer
    info "Timer installed: bad-collect.timer (schedule: $schedule)"
    info "Service unit:  $service_unit"
    info "Timer unit:    $timer_unit"
    echo "${C_DIM}Remove later: systemctl disable --now bad-collect.timer && rm $service_unit $timer_unit${C_RESET}"
}

# ---------------------------------------------------------------------------
# Step 9: Summary. What we did, what we did not, and what to do next.
# ---------------------------------------------------------------------------

summary() {
    banner "Installation summary"

    echo "  Binary:    ${BIN_DIR}/bad"
    echo "  Config:    ${CONFIG_DIR}/config.toml"
    echo "  Data dir:  ${DATA_DIR}"
    echo "  Service:   ${SERVICE_USER}"
    if [[ "$TIMER_INSTALL" == "y" ]]; then
        echo "  Timer:     bad-collect.timer (installed and enabled)"
    else
        echo "  Timer:     none (BAD runs when you run it)"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. ${BIN_DIR}/bad check-config --config ${CONFIG_DIR}/config.toml"
    echo "  2. sudo -u ${SERVICE_USER} ${BIN_DIR}/bad collect --platform linux --output ${DATA_DIR}/events.jsonl"
    echo "  3. ${BIN_DIR}/bad train --input ${DATA_DIR}/events.jsonl --output ${DATA_DIR}/model.joblib"
    echo ""
    echo "No daemon was installed. No service lingers. BAD runs when you run it,"
    echo "and stops when it is done, which is the only kind of tool worth running twice."
}

# ---------------------------------------------------------------------------
# Main: steps in order, each one honest about what it is about to do.
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo "${C_BOLD}BAD: Behavior Anomaly Detection - interactive Linux installer${C_RESET}"
    echo "${C_DIM}You will be asked before anything changes. Say no to anything you do not like.${C_RESET}"

    preflight
    detect_package_manager
    check_journal
    check_auditd
    setup_service_user
    install_binary
    install_config
    setup_data_dir
    offer_timer
    summary
}

main "$@"
