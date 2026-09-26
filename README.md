# BAD: Behavior Anomaly Detection

Cross-platform user behavior analytics for **Linux, Windows and macOS**.

Collect telemetry, normalize it, train on what users normally do, and hand
your SIEM a vendor-neutral alert when they stop doing that. A tool for agents,
SIEMs and monitoring stacks, not an agent itself.

The import package is `behavior_anomaly`, so nobody ever has to type
`from bad import Alert` with a straight face. The CLI, the distribution and
the executables are all `bad`.

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

The package separates collection, normalization, feature extraction, modeling,
detection, storage and SIEM transport so each layer can evolve independently,
and so a bug in one layer cannot moonlight as a bug in another.

## Principles

- **Vendor-neutral findings.** No Splunk-isms, no Sentinel-isms. Alerts are a
  typed JSON shape any SIEM, XDR or agent can consume. An ECS mapping ships
  with the package for the Elastic-inclined.
- **Tool, not agent.** It has no daemon, no persistence of its own beyond
  files you point it at, and no opinion about where it runs. Feed it events,
  get verdicts.
- **Conservative collectors.** Entries we cannot identify get skipped, not
  guessed. A tool that hallucinates telemetry is worse than no tool.
- **Privacy by construction.** Input dynamics (typing cadence, mouse motion)
  are aggregates only, reported by an agent over the JSONL front door. BAD
  never records keystrokes and never reads content. There is no option to
  turn it on, on any platform, ever.
- **One TOML config.** `config.example.toml` documents every toggle: detection
  knobs, SIEM sink, input dynamics on/off. Flags beat the file, the file
  beats the defaults.

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
```

## Documentation

The full documentation lives in the `docs` directory and is published to
GitHub Pages and ReadTheDocs via mkdocs:

```bash
pip install -e '.[docs]'
mkdocs serve    # live preview at http://localhost:8000
```

Deploying to a fleet? [Deployment](docs/deployment.md) covers prerequisites
per platform, and the `deploy/` directory ships the templates: a PowerShell
installer plus Intune packaging for Windows, an ansible role and a plain
`install.sh` for Linux, and a pkg recipe plus `install.sh` for macOS MDMs.
BAD installs no service and schedules nothing; your platform's scheduler runs
it on the cadence you chose, which is the "tool, not agent" contract with the
boring parts already written for you.

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

The baseline is an Isolation Forest trained over per-user, per-host time
windows. The model interface is intentionally replaceable, so per-user
baselines, temporal models, clustering or supervised classifiers can move in
without touching anything outside their own module.

## License

MIT, see [LICENSE](LICENSE). SPDX-License-Identifier: MIT. If you need a
lawyer to read it first, that is a you problem, and also correct.