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
import logging
import threading
from pathlib import Path

import typer
from pydantic import ValidationError

from behavior_anomaly import pipeline
from behavior_anomaly.collectors import build_collector
from behavior_anomaly.config import AppConfig
from behavior_anomaly.daemon import install_signal_handlers, run_loop
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
    of lie that shows up in an incident report. A config that fails
    validation (an unknown SIEM kind, a webhook without an endpoint, an
    out-of-range knob) is reported as a clean CLI error, not a traceback.
    """
    if config is None:
        try:
            return AppConfig()
        except ValidationError as exc:
            raise typer.BadParameter(str(exc)) from exc
    if not config.exists():
        raise typer.BadParameter(f"config file not found: {config}")
    try:
        return AppConfig.load(config)
    except ValidationError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def collect(
    platform: str = typer.Option(..., help="Collector: linux, windows, macos or jsonl"),
    output: Path = typer.Option(..., help="JSONL file to append collected events to"),
    # One parameter, two names: --source for the jsonl collector (a file
    # path) and --since for the linux collector (a journalctl time string).
    # The docs promised --since, so the option now keeps that promise.
    source: str | None = typer.Option(
        None, "--source", "--since", help="JSONL path for jsonl, --since value for linux"
    ),
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
    detection = app_config.detection.model_copy(
        update={
            key: value
            for key, value in {
                "window_seconds": window_seconds,
                "contamination": contamination,
                "min_events": min_events,
            }.items()
            if value is not None
        }
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
        try:
            detection = detection.model_copy(update={"anomaly_threshold": threshold})
        except ValidationError as exc:
            raise typer.BadParameter(str(exc)) from exc
    features = pipeline.build_features(app_config)

    events = JsonlStore(input).iter_events()
    alerts = pipeline.detect(events, load_model(model), detection, features=features)

    if output is not None:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if ecs:
            # ECS on disk too, so a downstream ECS consumer wired to --output
            # is not silently handed the native Alert schema.
            with output_path.open("w", encoding="utf-8") as fh:
                for alert in alerts:
                    fh.write(json.dumps(to_ecs(alert)) + "\n")
        else:
            JsonlAlertStore(output).write(alerts)
    else:
        # No output file: print alerts to stdout. With --output we stay quiet
        # on stdout (just the count) so piping the file is not duplicated.
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
        try:
            detection = detection.model_copy(update={"anomaly_threshold": threshold})
        except ValidationError as exc:
            raise typer.BadParameter(str(exc)) from exc
    features = pipeline.build_features(app_config)

    siem_config = app_config.siem
    try:
        siem_config = siem_config.model_copy(
            update={
                key: value
                for key, value in {"kind": siem, "endpoint": endpoint, "api_key": api_key}.items()
                if value is not None
            }
        )
    except ValidationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    sink = build_sink(siem_config)

    try:
        events = JsonlStore(input).iter_events()
        alerts = pipeline.monitor(events, load_model(model), detection, sink, features=features)
    finally:
        if hasattr(sink, "close"):
            sink.close()
    typer.echo(f"Sent {len(alerts)} alert(s) to the {siem_config.kind} sink")


@app.command()
def daemon(
    config_path: Path | None = typer.Option(None, "--config", help=CONFIG_HELP),
    once: bool = typer.Option(
        False,
        "--once",
        help="Run a single cycle and exit. For cron, testing, or the impatient.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log at DEBUG instead of INFO."),
) -> None:
    """Run the continuous monitoring daemon.

    Collects fresh telemetry, scores it against a trained model, ships alerts
    to the SIEM, and retrains periodically. All three stages are enabled by
    default and configurable via the [daemon] section of the TOML config.

    Use --once to run a single cycle (useful for cron or smoke tests). Without
    --once the daemon loops forever until Ctrl-C or SIGTERM, which is the
    whole point of a daemon. If you wanted one-shot, the other commands are
    right there.
    """
    app_config = load_config(config_path)
    daemon_config = app_config.daemon

    if not daemon_config.enabled:
        typer.echo("Daemon is disabled in config. Set [daemon] enabled = true to start it.")
        raise typer.Exit(code=1)

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if once:
        # One cycle, no loop, no signal handling. The training-wheels mode.
        from behavior_anomaly.daemon import DaemonState, run_cycle
        from behavior_anomaly.siem import build_sink as _build_once_sink

        # Build the sink once and close it so a webhook connection pool is
        # not left dangling (run_cycle itself never closes an injected sink,
        # because run_loop reuses one across cycles).
        sink = None
        if daemon_config.monitor.enabled:
            try:
                sink = _build_once_sink(app_config.siem)
            except Exception as exc:
                typer.echo(f"Could not build the SIEM sink: {exc}")
                raise typer.Exit(code=1) from exc
        try:
            result = run_cycle(app_config, DaemonState(), sink=sink)
        finally:
            if sink is not None and hasattr(sink, "close"):
                sink.close()
        typer.echo(
            f"cycle={result.cycle} collected={result.collected} "
            f"trained={result.trained} scored={result.scored} "
            f"alerts={result.alerts}"
        )
        if result.skipped:
            typer.echo(f"skipped: {', '.join(result.skipped)}")
        return

    stop_event = threading.Event()
    install_signal_handlers(stop_event)
    run_loop(app_config, stop_event=stop_event)


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
    daemon = app_config.daemon

    typer.echo(f"config OK: {config_path}")
    typer.echo(
        f"  detection: window={detection.window_seconds}s "
        f"threshold={detection.anomaly_threshold} "
        f"contamination={detection.contamination} "
        f"min_events={detection.min_events}"
    )
    typer.echo(
        f"  siem: kind={siem.kind} endpoint_set={siem.endpoint is not None}"
    )
    typer.echo(
        f"  input_dynamics: enabled={input_dynamics.enabled} "
        f"sampler_interval={input_dynamics.sampler_interval_seconds}s"
    )
    typer.echo(
        f"  daemon: enabled={daemon.enabled} "
        f"interval={daemon.interval_seconds}s "
        f"collect={daemon.collect.enabled} "
        f"train={daemon.train.enabled} "
        f"monitor={daemon.monitor.enabled}"
    )


if __name__ == "__main__":
    app()
