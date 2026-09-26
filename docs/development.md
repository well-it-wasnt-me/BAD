# Development

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

pytest           # run the suite
ruff check .     # lint, 120 columns
mypy             # types
```

If it is not tested, it is broken; we just do not know where yet. Every
module has a matching test file, and the CI matrix (3.11, 3.12, 3.13) checks
lint, types and tests on every push and pull request.

## House rules

- **KISS and SOLID.** One interface per layer, one job per module. If you
  need a diagram to explain a function, the function is the diagram.
- **Pure parsers, impure plumbing.** OS collectors split parsing (pure,
  dict in, event out, testable anywhere) from subprocess plumbing. Keep the
  plumbing starving.
- **Never invent telemetry.** Collectors skip what they cannot identify.
  Silence beats fiction.
- **Keep the docs true.** `mkdocs serve` previews this site. Docs that lie
  are worse than no docs; they are marketing.

## Docs

Documentation is mkdocs with the readthedocs theme, published to GitHub
Pages by `.github/workflows/docs.yml` and buildable by ReadTheDocs via
`.readthedocs.yaml`.

```bash
pip install -e '.[docs]'
mkdocs serve    # live preview at http://localhost:8000
```

Build runs with `--strict`, so a broken link fails CI. Docs that are not
published are diaries.

## Commits and releases

Commits follow the conventional style: `feat:`, `fix:`, `chore:`, `docs:`,
`test:`, `refactor:`. The release workflow (`release.yml`) reads them with
python-semantic-release:

- `feat:` bumps the minor version, `fix:` bumps the patch, and a
  `BREAKING CHANGE` footer bumps the major.
- The version bumps in **both** `pyproject.toml` and
  `src/behavior_anomaly/__init__.py`, because two sources of truth is one
  too many.
- `CHANGELOG.md` regenerates itself from the commits on every release.
- On each release, a three OS matrix builds standalone executables with
  PyInstaller: a Linux binary, a Windows exe and a macOS dmg, attached to
  the GitHub release. A tool nobody can run is a hobby.

So: write honest commit messages and the robots do the paperwork. The
robots are into that kind of thing.

## Executables locally

Same recipe CI uses, minus the yaml:

```bash
pip install -e '.[build]'
pyinstaller --onefile --name bad --collect-all sklearn --collect-all scipy \
    --paths src src/behavior_anomaly/__main__.py
```

Fair warning: sklearn makes the binary chunky. Blame the trees.