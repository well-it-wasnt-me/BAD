<#
.SYNOPSIS
    BAD interactive Windows installer.

.DESCRIPTION
    The non-interactive Install-BAD.ps1 is for fleets, Intune packaging and
    config management: no questions, same steps every time. This script is
    for the human at the keyboard who wants to be asked before anything
    touches their machine. It checks, it asks, it acts only with permission,
    and it says exactly what it did.

    What it does NOT do: install a service, a driver, a watchdog, or anything
    that outlives this script, unless you explicitly say yes to the optional
    Task Scheduler job at the end. BAD runs when something runs it.

    Read it before you run it. It is shorter than the incident report from
    not reading it, and unlike the incident report, you get to say no.

.PARAMETER Repo
    GitHub repo the release artifacts live in.

.PARAMETER Version
    "latest" resolves to the newest tagged release. Pin a version for a
    fleet: reproducibility beats novelty.

.PARAMETER InstallDir
    Where the binary lands. Change here once, not in five scripts.

.PARAMETER ConfigDir
    Where the config lands.

.PARAMETER DataDir
    Where collect writes its JSONL output.

.PARAMETER ServiceAccount
    The account that will run `bad collect`. Added to Event Log Readers so
    it can read the Security log WITHOUT being an admin.

.PARAMETER ArtifactPath
    Path to a bad-windows.exe you already downloaded (offline clients,
    Intune bundles). Leave empty to download from the release instead.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Install-BAD-Interactive.ps1
#>

param(
    [string]$Repo = "https://github.com/well-it-wasnt-me/BAD",
    [string]$Version = "latest",
    [string]$InstallDir = "C:\Program Files\BAD",
    [string]$ConfigDir = "C:\ProgramData\BAD",
    [string]$DataDir = "C:\ProgramData\BAD\data",
    [string]$ServiceAccount = "BADSVC",
    [string]$ArtifactPath = ""
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers. Small, named, boring. The way helpers should be.
# ---------------------------------------------------------------------------

function Write-Banner($text) {
    # A section header. If this script had a theme song, this is where it played.
    Write-Host ""
    Write-Host "=== $text ===" -ForegroundColor White
}

function Write-Ok($text) {
    Write-Host "[ok]  $text" -ForegroundColor Green
}

function Write-Warn($text) {
    Write-Host "[warn] $text" -ForegroundColor Yellow
}

function Write-Fail($text) {
    Write-Host "[fail] $text" -ForegroundColor Red
    throw $text
}

function Ask-YesNo($prompt, $default = "n") {
    # Ask a yes/no question. Empty input takes the default, because decisions
    # are hard enough without making the default a guessing game.
    $hint = if ($default -eq "y") { "[Y/n]" } else { "[y/N]" }
    $response = Read-Host "$prompt $hint"
    if ([string]::IsNullOrWhiteSpace($response)) { $response = $default }
    return $response -match "^[yY]"
}

function Ask-Value($prompt, $defaultValue) {
    # Ask for a value. Empty input takes the default.
    $response = Read-Host "$prompt [$defaultValue]"
    if ([string]::IsNullOrWhiteSpace($response)) { return $defaultValue }
    return $response
}

function Test-Administrator {
    # Are we elevated? The install writes to Program Files and ProgramData,
    # so root-adjacent privilege is not optional. The service account BAD
    # actually runs as is unprivileged; this is just the key to the door.
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Step 0: Preflight. Are we even on the right planet?
# ---------------------------------------------------------------------------

function Invoke-Preflight {
    Write-Banner "Preflight checks"

    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne "Win32NT") {
        Write-Fail "This installer is Windows only. You are on $($PSVersionTable.Platform). The Linux and macOS installers live in deploy/linux/ and deploy/macos/."
    }
    Write-Ok "Operating system: Windows"

    if (-not (Test-Administrator)) {
        Write-Fail "This installer writes to $InstallDir and $ConfigDir. Run elevated: right-click PowerShell, 'Run as administrator'."
    }
    Write-Ok "Running elevated (install only; BAD itself runs unprivileged)"
}

# ---------------------------------------------------------------------------
# Step 1: VC++ Redistributable. PyInstaller bundles the Python runtime, but
# numpy and scikit-learn are compiled with MSVC and ship DLLs that depend on
# the Visual C++ runtime. A clean Windows box without VC++ Redist will see
# "bad.exe failed to start" and nothing else, which is the least helpful
# error message Microsoft ever shipped, and that is a high bar.
# ---------------------------------------------------------------------------

function Install-VcRedist {
    Write-Banner "Visual C++ Redistributable (runtime for numpy and scikit-learn)"

    # Check the registry for an installed VC++ Redistributable x64.
    # The key has moved around between versions; we check both 14.0 and 17.0
    # because Microsoft's naming scheme is a gift that keeps on giving.
    $vcPaths = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\17.0\VC\Runtimes\x64"
    )
    $vcInstalled = $false
    foreach ($path in $vcPaths) {
        if (Test-Path $path) {
            $vcInstalled = $true
            $version = (Get-ItemProperty $path).Version
            Write-Ok "VC++ Redistributable x64 found (version $version)"
            break
        }
    }

    # Belt and suspenders: also check for the actual DLL, because some
    # installs register differently than the registry promises.
    if (-not $vcInstalled -and (Test-Path "C:\Windows\System32\vcruntime140_1.dll")) {
        $vcInstalled = $true
        Write-Ok "VC++ Redistributable x64 found (vcruntime140_1.dll present)"
    }

    if ($vcInstalled) { return }

    Write-Warn "VC++ Redistributable x64 not found."
    Write-Warn "numpy and scikit-learn need it. Without it, bad.exe will not start."
    Write-Warn "The error will be unhelpful. The fix is a one-time download."

    if (-not (Ask-YesNo "Download and install VC++ Redistributable x64?" "y")) {
        Write-Warn "Skipping. bad.exe may fail to start. Install it manually if it does:"
        Write-Warn "  https://aka.ms/vs/17/release/vc_redist.x64.exe"
        return
    }

    $vcUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcPath = Join-Path $env:TEMP "vc_redist.x64.exe"

    Write-Host "Downloading $vcUrl ..."
    Invoke-WebRequest -Uri $vcUrl -OutFile $vcPath -UseBasicParsing

    Write-Host "Installing VC++ Redistributable (silent, no restart)..."
    # /install /quiet /norestart: the only three flags that matter. The rest
    # of the documentation is a personality test.
    $process = Start-Process -FilePath $vcPath -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 1638) {
        # 1638 means "a newer version is already installed", which is a win
        # wearing a confusing hat.
        Write-Ok "VC++ Redistributable installed"
    } else {
        Write-Warn "VC++ Redistributable installer exited with code $($process.ExitCode)."
        Write-Warn "It may already be installed, or the install may need a reboot."
        Write-Warn "If bad.exe fails to start, install it manually from the URL above."
    }
}

# ---------------------------------------------------------------------------
# Step 2: Service account. BAD never wants admin. The account that runs
# collect gets Event Log Readers membership and nothing else, which is the
# boring correct privilege for reading the Security log.
# ---------------------------------------------------------------------------

function Setup-ServiceAccount {
    Write-Banner "Service account (unprivileged, reads the Security log)"

    $script:ServiceAccount = Ask-Value "Service account name" $ServiceAccount

    $user = Get-LocalUser -Name $script:ServiceAccount -ErrorAction SilentlyContinue
    if ($user) {
        Write-Ok "User '$script:ServiceAccount' already exists"
    } else {
        if (Ask-YesNo "Create local user '$script:ServiceAccount'?" "y") {
            # No password, cannot log in interactively. A service account
            # that can log in at the console is an attack surface with a
            # name tag. We only need it for batch/task-scheduler runs.
            try {
                New-LocalUser -Name $script:ServiceAccount `
                    -Description "BAD behavior collection (unprivileged)" `
                    -NoPassword -ErrorAction Stop | Out-Null
                Write-Ok "User '$script:ServiceAccount' created (no interactive login)"
            } catch {
                Write-Warn "Could not create user '$script:ServiceAccount'. $_"
                Write-Warn "Create it manually and re-run, or use an existing account."
                return
            }
        } else {
            Write-Warn "Skipping user creation. Collect will need an account to run as."
            return
        }
    }

    # Event Log Readers is the boring, correct answer for reading the
    # Security log. Admin-as-default is how security tools become findings.
    if (Ask-YesNo "Add '$script:ServiceAccount' to Event Log Readers (read Security log without admin)?" "y") {
        try {
            Add-LocalGroupMember -Group "Event Log Readers" -Member $script:ServiceAccount -ErrorAction Stop
            Write-Ok "'$script:ServiceAccount' added to Event Log Readers"
        } catch {
            Write-Warn "Could not add to Event Log Readers. $_"
            Write-Warn "The account may already be a member, or the group name differs on this locale."
        }
    } else {
        Write-Warn "Skipping group membership. Collect will need admin to read the Security log."
    }
}

# ---------------------------------------------------------------------------
# Step 3: Binary. Download the release exe, or use a local artifact for
# offline clients. Then smoke test it.
# ---------------------------------------------------------------------------

function Install-Binary {
    Write-Banner "BAD binary"

    $script:Version = Ask-Value "Version (or 'latest')" $Version
    $binPath = Join-Path $InstallDir "bad.exe"

    if (Test-Path $binPath) {
        if (-not (Ask-YesNo "Binary already exists at $binPath. Overwrite?" "n")) {
            Write-Ok "Keeping existing binary at $binPath"
            return
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    if ($ArtifactPath -ne "" -and (Test-Path $ArtifactPath)) {
        Write-Host "Installing from local artifact: $ArtifactPath"
        Copy-Item $ArtifactPath $binPath -Force
    } else {
        $artifact = if ($script:Version -eq "latest") {
            "$Repo/releases/latest/download/bad-windows.exe"
        } else {
            "$Repo/releases/download/$($script:Version)/bad-windows.exe"
        }
        Write-Host "Downloading $artifact ..."
        Invoke-WebRequest -Uri $artifact -OutFile $binPath -UseBasicParsing
    }

    Write-Ok "Binary installed to $binPath"

    # The binary must prove it runs before we call this an install. A deploy
    # log entry is a better place to learn the truth than 3 AM.
    & $binPath --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Binary failed its own --help. The download may be corrupt, the architecture wrong, or VC++ Redistributable is missing."
    }
    Write-Ok "Binary smoke test passed (bad --help)"
}

# ---------------------------------------------------------------------------
# Step 4: Config. Drop the example if none exists. Never overwrite an
# existing config: an admin who tuned thresholds does not want a reinstall
# to reset their opinions.
# ---------------------------------------------------------------------------

function Install-Config {
    Write-Banner "Configuration"

    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    $configPath = Join-Path $ConfigDir "config.toml"

    if (Test-Path $configPath) {
        Write-Ok "Config already exists at $configPath, left untouched"
        if (Ask-YesNo "Edit it now with the default editor?" "n") {
            $editor = if ($env:EDITOR) { $env:EDITOR } else { "notepad" }
            Write-Host "Opening $configPath with $editor ..."
            Start-Process -FilePath $editor -ArgumentList $configPath -Wait
        }
    } else {
        $configUrl = "$Repo/raw/main/config.example.toml"
        Write-Host "Downloading config template to $configPath ..."
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
        Write-Ok "Config template written to $configPath"
        Write-Host "Edit it to set your SIEM sink, detection thresholds, and input dynamics." -ForegroundColor DarkGray
        if (Ask-YesNo "Edit it now with the default editor?" "y") {
            $editor = if ($env:EDITOR) { $env:EDITOR } else { "notepad" }
            Write-Host "Opening $configPath with $editor ..."
            Start-Process -FilePath $editor -ArgumentList $configPath -Wait
        }
    }

    # Validate before we declare victory.
    $binPath = Join-Path $InstallDir "bad.exe"
    & $binPath check-config --config $configPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Config validated successfully"
    } else {
        Write-Warn "Config validation failed. Run: $binPath check-config --config $configPath"
        Write-Warn "Fix the config and re-run, or BAD will discover the typo at 3 AM instead of you."
    }
}

# ---------------------------------------------------------------------------
# Step 5: Data directory. Where collect writes its JSONL.
# ---------------------------------------------------------------------------

function Setup-DataDir {
    Write-Banner "Data directory"

    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $acl = Get-Acl $DataDir
    # Give the service account full control of the data dir, because it
    # writes there. Nobody else needs it.
    try {
        $user = Get-LocalUser -Name $script:ServiceAccount -ErrorAction Stop
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $script:ServiceAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $DataDir -AclObject $acl
        Write-Ok "Data directory $DataDir (full control: $script:ServiceAccount)"
    } catch {
        Write-Ok "Data directory $DataDir (ownership skipped: user '$script:ServiceAccount' does not exist)"
    }
}

# ---------------------------------------------------------------------------
# Step 6 (optional): Task Scheduler job. BAD installs no service and
# schedules nothing by default. This is the one place the installer offers
# to bend that rule, and only because the admin is standing right here.
# ---------------------------------------------------------------------------

function Invoke-OptionalTask {
    Write-Banner "Optional: Task Scheduler collection job"

    Write-Host "BAD runs when something runs it. A scheduled task is one way"
    Write-Host "to make something run it on a cadence. This is optional and fully reversible."
    Write-Host ""

    if (-not (Ask-YesNo "Install a scheduled task for nightly collection?" "n")) {
        Write-Ok "No scheduled task installed. BAD runs when you run it."
        $script:TaskInstalled = $false
        return
    }

    $script:TaskInstalled = $true
    $time = Ask-Value "Schedule time (24h, e.g. 23:15)" "23:15"
    $taskName = "BAD-Collect"
    $binPath = Join-Path $InstallDir "bad.exe"
    $outputPath = Join-Path $DataDir "events.jsonl"

    $action = New-ScheduledTaskAction -Execute $binPath `
        -Argument "collect --platform windows --output `"$outputPath`""
    $trigger = New-ScheduledTaskTrigger -Daily -At $time

    try {
        # Register as the service account if it exists, otherwise as SYSTEM.
        # SYSTEM is overkill but works; the whole point of the service account
        # was to not need it, so prefer that if present.
        $user = Get-LocalUser -Name $script:ServiceAccount -ErrorAction SilentlyContinue
        if ($user) {
            # "Log on as a batch job" is needed for a non-interactive account.
            # We grant it here; without it, Task Scheduler refuses to run.
            Grant-LogOnAsBatch $script:ServiceAccount
            $principal = New-ScheduledTaskPrincipal -User $script:ServiceAccount `
                -LogonType Batch -RunLevel Limited
            Register-ScheduledTask -TaskName $taskName `
                -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        } else {
            Register-ScheduledTask -TaskName $taskName `
                -Action $action -Trigger $trigger -Force | Out-Null
        }
        Write-Ok "Scheduled task installed: $taskName (daily at $time)"
        Write-Host "Remove later: Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false" -ForegroundColor DarkGray
    } catch {
        Write-Warn "Could not create scheduled task: $_"
        Write-Warn "Create it manually via Task Scheduler or Group Policy."
        $script:TaskInstalled = $false
    }
}

function Grant-LogOnAsBatch($username) {
    # Grant "Log on as a batch job" right via secedit. Task Scheduler needs
    # this for accounts that cannot log in interactively. Without it, the
    # task silently fails to start, which is Microsoft's way of saying
    # "good luck finding this in the GUI".
    try {
        $tempConfig = Join-Path $env:TEMP "bad_secedit.cfg"
        $tempDb = Join-Path $env:TEMP "bad_secedit.sdb"
        # Export current policy
        secedit /export /cfg $tempConfig /quiet
        # Append the right
        $content = Get-Content $tempConfig -Raw
        if ($content -notmatch "SeBatchLogonRight") {
            $content += "`nSeBatchLogonRight = *$username`n"
        } else {
            $content = $content -replace "SeBatchLogonRight\s*=\s*(.*)", "SeBatchLogonRight = `$1,*$username"
        }
        Set-Content $tempConfig -Value $content
        secedit /configure /db $tempDb /cfg $tempConfig /quiet
    } catch {
        Write-Warn "Could not grant 'Log on as a batch job' to $username. The task may not start."
        Write-Warn "Grant it manually via Local Security Policy > User Rights Assignment."
    }
}

# ---------------------------------------------------------------------------
# Step 7: Summary. What we did, what we did not, and what to do next.
# ---------------------------------------------------------------------------

function Show-Summary {
    Write-Banner "Installation summary"

    Write-Host "  Binary:    $InstallDir\bad.exe"
    Write-Host "  Config:    $ConfigDir\config.toml"
    Write-Host "  Data dir:  $DataDir"
    Write-Host "  Service:   $script:ServiceAccount"
    if ($script:TaskInstalled) {
        Write-Host "  Schedule:  Task Scheduler 'BAD-Collect' (installed)"
    } else {
        Write-Host "  Schedule:  none (BAD runs when you run it)"
    }
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. $InstallDir\bad.exe check-config --config $ConfigDir\config.toml"
    Write-Host "  2. $InstallDir\bad.exe collect --platform windows --output $DataDir\events.jsonl"
    Write-Host "  3. $InstallDir\bad.exe train --input $DataDir\events.jsonl --output $DataDir\model.joblib"
    Write-Host ""
    Write-Host "No service was installed. No watchdog lingers. BAD runs when you"
    Write-Host "run it, and stops when it is done, which is the only kind of tool"
    Write-Host "worth running twice."
}

# ---------------------------------------------------------------------------
# Main: steps in order, each one honest about what it is about to do.
# ---------------------------------------------------------------------------

$script:ServiceAccount = $ServiceAccount
$script:Version = $Version
$script:TaskInstalled = $false

Write-Host ""
Write-Host "BAD: Behavior Anomaly Detection - interactive Windows installer" -ForegroundColor White
Write-Host "You will be asked before anything changes. Say no to anything you do not like." -ForegroundColor DarkGray

Invoke-Preflight
Install-VcRedist
Setup-ServiceAccount
Install-Binary
Install-Config
Setup-DataDir
Invoke-OptionalTask
Show-Summary
