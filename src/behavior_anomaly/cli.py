"""Command line interface.

Thin as we can make it: parse arguments, load config, call the pipeline, print
results. All real logic lives in behavior_anomaly.pipeline so anything with a
Python interpreter can drive the same pipeline directly. A CLI is a
convenience, not a personality.

Precedence is boring and predictable: defaults < TOML config file < command
line flags. The flags are all None until someone types them, so anything the
admin set in the file survives unless the human on the keyboard says otherwise.
"""

import json
from pathlib import Path

import typer

from behavior_anomaly import pipeline
from behavior_anomaly.collectors import build_collector
from behavior_anomaly.config import AppConfig
from behavior_anomaly.models.persistence import load_model, save_model
from behavior_anomaly.siem import build_sink
from behavior_anomaly.siem.ecs import to_ecs
from behavior_anomaly.storage.alerts import JsonlAlertStore
from behavior_anomaly.storage.jsonl import JsonlStore

app = typer.Typer(
    no_args_is_help=True,
    help="BAD: Behavior Anomaly Detection. Cross-platform user behavior analytics for SIEMs.",
)

CONFIG_HELP = "Admin TOML config file (see config.example.toml). Flags override it."


def load_config(config: Path | None) -> AppConfig:
    """Load the admin config, or defaults when no file was given.

    A config file that does not exist is an error, not a silent default: the
    admin pointed at a file, and pretending we honored it would be the kind
    of lie that shows up in an incident report.
    """
    if config is None:
        return AppConfig()
    if not config.exists():
        raise typer.BadParameter(f"config file not found: {config}")
    return AppConfig.load(config)


@app.command()
def collect(
    platform: str = typer.Option(..., help="Collector: linux, windows, macos or jsonl"),
    output: Path = typer.Option(..., help="JSONL file to append collected events to"),
    source: str | None = typer.Option(None, help="JSONL path for jsonl, --since value for linux"),
) -> None:
    """Collect events from the local OS or a normalized JSONL file."""
    collector = build_collector(platform, source)
    events = list(collector.collect())
    JsonlStore(output).write(events)
    typer.echo(f"Collected {len(events)} event(s) into {output}")


@app.command()
def train(
    input: Path = typer.Option(..., exists=True, help="Normalized events (JSONL)"),
    output: Path = typer.Option(..., help="Where to write the trained model"),
    config_path: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
    window_seconds: int | None = typer.Option(None, help="Behavior window size in seconds"),
    contamination: float | None = typer.Option(None, help="Expected anomaly fraction in training data"),
    min_events: int | None = typer.Option(None, help="Minimum events per window to train on"),
) -> None:
    """Train an anomaly model from normalized events."""
    app_config = load_config(config_path)
    # Command line flags win over the config file, but only where typed.
    overrides = {
        "window_seconds": window_seconds,
        "contamination": contamination,
        "min_events": min_events,
    }
    detection = app_config.detection.model_copy(
        update={key: value for key, value in overrides.items() if value is not None}
    )
    features = pipeline.build_features(app_config)

    events = JsonlStore(input).iter_events()
    model = pipeline.train_model(events, detection, features=features)
    save_model(model, output)
    typer.echo(f"Trained {model.name} -> {output}")


@app.command()
def score(
    input: Path = typer.Option(..., exists=True, help="Normalized events (JSONL)"),
    model: Path = typer.Option(..., exists=True, help="Trained model file"),
    config_path: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
    threshold: float | None = typer.Option(None, help="Anomaly score threshold for alerting"),
    output: Path | None = typer.Option(None, help="Write alerts (JSONL) to this file"),
    ecs: bool = typer.Option(False, "--ecs", help="Print alerts as ECS-flavored JSON"),
) -> None:
    """Score events with a trained model and print the resulting alerts."""
    app_config = load_config(config_path)
    detection = app_config.detection
    if threshold is not None:
        detection = detection.model_copy(update={"anomaly_threshold": threshold})
    features = pipeline.build_features(app_config)

    events = JsonlStore(input).iter_events()
    alerts = pipeline.detect(events, load_model(model), detection, features=features)

    if output is not None:
        JsonlAlertStore(output).write(alerts)

    for alert in alerts:
        rendered = to_ecs(alert) if ecs else json.loads(alert.model_dump_json())
        typer.echo(json.dumps(rendered))
    typer.echo(f"{len(alerts)} alert(s)")


@app.command()
def monitor(
    input: Path = typer.Option(..., exists=True, help="Normalized events (JSONL)"),
    model: Path = typer.Option(..., exists=True, help="Trained model file"),
    config_path: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
    threshold: float | None = typer.Option(None, help="Anomaly score threshold for alerting"),
    siem: str | None = typer.Option(None, help="SIEM sink: webhook or syslog"),
    endpoint: str | None = typer.Option(None, help="HTTP endpoint for the webhook sink"),
    api_key: str | None = typer.Option(None, help="Bearer token for the webhook sink"),
) -> None:
    """Score events and send every alert to a SIEM sink."""
    app_config = load_config(config_path)
    detection = app_config.detection
    if threshold is not None:
        detection = detection.model_copy(update={"anomaly_threshold": threshold})
    features = pipeline.build_features(app_config)

    siem_config = app_config.siem
    sink_overrides = {
        "kind": siem,
        "endpoint": endpoint,
        "api_key": api_key,
    }
    siem_config = siem_config.model_copy(
        update={key: value for key, value in sink_overrides.items() if value is not None}
    )
    sink = build_sink(siem_config)

    events = JsonlStore(input).iter_events()
    alerts = pipeline.monitor(events, load_model(model), detection, sink, features=features)
    typer.echo(f"Sent {len(alerts)} alert(s) to the {siem_config.kind} sink")


@app.command("check-config")
def check_config(
    config_path: Path = typer.Option(..., "--config", help="Admin TOML config file to validate"),
) -> None:
    """Validate a config file and print the effective settings.

    Built for deployment tooling: ansible handlers, install scripts, MDM
    wrappers. It proves the admin's TOML parses and validates before a
    scheduled run discovers the truth at 3 AM on someone else's pager.
    """
    app_config = load_config(config_path)

    detection = app_config.detection
    siem = app_config.siem
    input_dynamics = app_config.input_dynamics

    typer.echo(f"config OK: {config_path}")
    typer.echo(
        f"  detection: window={detection.window_seconds}s "
        f"threshold={detection.anomaly_threshold} "
        f"contamination={detection.contamination} "
        f"min_events={detection.min_events}"
    )
    typer.echo(
        f"  siem: kind={siem.kind} endpoint_set={siem.endpoint is not None} "
        f"api_key_set={siem.api_key is not None}"
    )
    typer.echo(
        f"  input_dynamics: enabled={input_dynamics.enabled} "
        f"sampler_interval={input_dynamics.sampler_interval_seconds}s"
    )


if __name__ == "__main__":
    app()
