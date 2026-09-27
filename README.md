# BAD: Behavior Anomaly Detection

Cross-platform user behavior analytics for **Linux, Windows and macOS**.

Collect telemetry, normalize it, train on what users normally do, and hand your SIEM a vendor-neutral alert when 
they stop doing that. A tool for agents, SIEMs and monitoring stacks, not an agent itself.

The import package is `behavior_anomaly`, so nobody ever has to type `from bad import Alert` with a straight face. 
The CLI and the executables are `bad`. 
The pip distribution is `behavior-anomaly-detection`, because someone parked a dead Android driver on the name `bad` 
in 2018 and PyPI keeps names forever, like a dragon with worse taste in treasure.

## The pipeline

```text
Linux / Windows / macOS
          |
          v
     OS collectors  or  normalized JSONL from your agent
          |
          v
    BehaviorEvent  (the one schema that rules them all)
          |
          v
   feature extraction  (per user, per host, per time window)
          |
          v
     trained model  (Isolation Forest baseline)
          |
          v
     anomaly score
          |
          v
   detection policy  (thresholds, severities, evidence)
          |
          v
        Alert  (vendor-neutral, typed, boring on purpose)
          |
          v
   SIEM sink  (webhook or syslog, ECS mapping included)
```

The package separates collection, normalization, feature extraction, modeling, detection, storage and SIEM transport 
so each layer can evolve independently, and so a bug in one layer cannot moonlight as a bug in another.

## Principles

- **Vendor-neutral findings.** No Splunk-isms, no Sentinel-isms. Alerts are a
  typed JSON shape any SIEM, XDR or agent can consume. An ECS mapping ships
  with the package for the Elastic-inclined.
- **Tool, not agent (but it can loop).** The CLI commands are one-shot verbs
  you wire into your own scheduler. The optional daemon command loops
  collect, train and monitor on a timer, all enabled by default and
  configurable via the [daemon] section of the TOML config. Feed it events,
  get verdicts, on your schedule or its own.
- **Conservative collectors.** Entries we cannot identify get skipped, not
  guessed. A tool that hallucinates telemetry is worse than no tool.
- **Privacy by construction.** Input dynamics (typing cadence, mouse motion)
  are aggregates only, reported by an agent over the JSONL front door. BAD
  never records keystrokes and never reads content. There is no option to
  turn it on, on any platform, ever.
- **One TOML config.** `config.example.toml` documents every toggle: detection
  knobs, SIEM sink, input dynamics on/off. Flags beat the file, the file
  beats the defaults.

## The signal nobody else listens for

Process and auth telemetry tells you *what* a user did. Typing cadence and mouse motion tell you *who* was at the keyboard. 
A hijacked session almost always types and mouses differently from the legitimate owner, no matter how careful 
the attacker is about which commands they run. Pure process telemetry is deaf to that signal. 
BAD is not.

BAD derives behavioral biometrics from **typing cadence** (keystroke counts, mean and stddev of inter-key intervals, 
typing velocity) and **mouse movement patterns** (distance, speed, direction changes). 
These are aggregates only, reported by an agent over the JSONL front door. BAD never records keystrokes,
never reads content, and there is no option to turn that on, on any platform, ever. 
The timing of typing is a signature. The content of typing is a lawsuit.

This is the part that makes BAD more than a process-log counter with a threshold: the model can flag a session where 
the commands look normal but the human behind them does not. That is the difference between "something happened" and 
"someone else happened".

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

bad --help
pytest
```

A full worked session: collect (or hand over your agent's normalized JSONL),
train, score, monitor:

```bash
bad collect --platform jsonl --source agent-events.jsonl --output events.jsonl
bad train --input events.jsonl --output model.joblib
bad score --input events.jsonl --model model.joblib
bad monitor --input events.jsonl --model model.joblib --siem webhook --endpoint https://siem.example.test/hook

# Or run the continuous monitoring daemon (collects, scores, retrains, loops):
bad daemon --config /etc/bad/config.toml
bad daemon --once    # single cycle, for cron or smoke tests
```

## Documentation

The full documentation lives in the `docs` directory and is published to GitHub Pages and ReadTheDocs via mkdocs:

```bash
pip install -e '.[docs]'
mkdocs serve    # live preview at http://localhost:8000
```

Deploying to a fleet? [Deployment](docs/deployment.md) covers prerequisites per platform, and the `deploy/` directory ships the templates: 
a PowerShell installer plus Intune packaging for Windows, an ansible role and a plain `install.sh` for Linux, 
and a pkg recipe plus `install.sh` for macOS MDMs. 
BAD can run as a daemon (`bad daemon`) or as one-shot commands wired into your own scheduler;
your platform's scheduler runs it on the cadence you chose, which is the "tool, not agent" contract
with the boring parts already written for you. The daemon ships with systemd and cron examples.

## Releases

Releases are automated by conventional commits:

- `feat: ...` bumps the minor version, `fix: ...` bumps the patch,
  `BREAKING CHANGE` bumps the major. Chores do nothing, which is the nicest
  thing anyone has ever said about chores.
- The changelog (CHANGELOG.md) regenerates itself on release.
- Standalone executables (Linux binary, Windows exe, macOS dmg) build on
  every release and attach to the GitHub release. A tool nobody can run is
  a hobby.

## Model

The baseline is an Isolation Forest trained over per-user, per-host time windows. 
The model interface is intentionally replaceable, so per-user baselines, temporal models, clustering or 
supervised classifiers can move in without touching anything outside their own module.

## License

MIT, see [LICENSE](LICENSE). If you need a lawyer to read it first, that is a you problem, and also correct.