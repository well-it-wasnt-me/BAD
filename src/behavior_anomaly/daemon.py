"""Continuous monitoring daemon.

The daemon is the always-on half of BAD. Where the CLI commands are one-shot
verbs (collect, train, score, monitor), the daemon is a loop that does all
four on a timer, forever, or until someone tells it to stop.

The design is deliberately simple: one thread, one loop, one cycle at a time.
Each cycle runs collect -> train (if scheduled) -> monitor, then sleeps for
interval_seconds. No asyncio, no thread pool, no message queue. A daemon that
needs a load balancer to function is a daemon that has lost the plot.

Cycle logic is split from loop logic so tests can exercise one cycle without
waiting for the heat death of the universe. The loop is just a while-True with
a polite shutdown mechanism (threading.Event) so SIGINT and SIGTERM do not
leave the daemon in a half-written state.

Order matters: collect first (get fresh events), then train (build a model
from them if scheduled or if no model exists yet), then monitor (score the
new events and ship alerts). This way the very first cycle bootstraps a model
from whatever events it just collected, instead of refusing to work because
there is nothing to score against.
"""

from __future__ import annotations

import logging
import platform as _platform_module
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from behavior_anomaly.collectors import build_collector
from behavior_anomaly.config import AppConfig, DaemonConfig
from behavior_anomaly.models.persistence import load_model, save_model
from behavior_anomaly.pipeline import build_features, detect, train_model
from behavior_anomaly.schema import BehaviorEvent
from behavior_anomaly.siem import build_sink
from behavior_anomaly.siem.base import SiemSink
from behavior_anomaly.storage.jsonl import JsonlStore

logger = logging.getLogger("behavior_anomaly.daemon")

# How finely we slice the sleep so SIGINT arrives promptly. The daemon sleeps
# in chunks of this size, checking the stop flag between each, so the user
# never waits the full interval for Ctrl-C to register. Patience is a virtue,
# but not when you are standing at a terminal.
_SLEEP_GRANULARITY_SECONDS = 1.0


@dataclass
class DaemonState:
    """Mutable state carried between cycles.

    byte_offset: how far into events_file we have already scored. The daemon
        only scores events it has not seen yet, so it tracks the file position
        after each collect + monitor pass. Restarting the daemon re-scans
        from zero, which is safe (duplicate alerts, not missed alerts).

    cycle: monotonic cycle counter, used to decide when to retrain.
    """

    byte_offset: int = 0
    cycle: int = 0


@dataclass
class CycleResult:
    """What happened in one cycle. For logging, tests, and curious humans.

    Every field is a count or a flag, never an exception. If something blew
    up, the error is logged and the count reflects what got done before the
    explosion. The daemon does not crash on a single bad cycle; it logs,
    shrugs, and tries again next time. Resilience is not glamorous, but it
    is what keeps the lights on at 3 AM.
    """

    cycle: int
    collected: int = 0
    trained: bool = False
    scored: int = 0
    alerts: int = 0
    skipped: list[str] = field(default_factory=list)


def detect_platform() -> str:
    """Return the collector name for the running OS.

    Python's platform.system() is the cheapest cross-platform check that does
    not involve parsing /etc/os-release and praying. If it returns something
    we do not recognize, we raise, because guessing the OS is how you collect
    Windows event logs on a Linux box and wonder why nothing works.
    """
    system = _platform_module.system().lower()
    if system == "linux":
        return "linux"
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    raise ValueError(
        f"Cannot auto-detect platform from {system!r}. "
        "Set [daemon.collect] platform explicitly in your config."
    )


def _resolve_platform(config: DaemonConfig) -> str:
    """Pick the collector platform: explicit config or auto-detect."""
    if config.collect.platform is not None:
        return config.collect.platform
    return detect_platform()


def _collect_cycle(
    config: DaemonConfig,
    app_config: AppConfig,
) -> list[BehaviorEvent]:
    """Run the collector and append events to events_file.

    Returns the events collected so the caller can update state. Failures are
    logged and return an empty list: a bad collect cycle is not a reason to
    crash the daemon. The journal might be temporarily unreadable, journalctl
    might be having a moment, life happens. We try again next cycle.
    """
    platform_name = _resolve_platform(config)
    # Pick the right source argument per platform: jsonl wants a path,
    # linux wants a `--since` string, windows/macos take nothing.
    if platform_name == "jsonl":
        source = config.collect.source
    elif platform_name == "linux":
        source = config.collect.since
    else:
        source = None
    collector = build_collector(platform_name, source)
    events = list(collector.collect())
    if events:
        JsonlStore(config.events_file).write(events)
    return events


def _train_cycle(config: DaemonConfig, app_config: AppConfig) -> bool:
    """Retrain the model from the full event history.

    Returns True if training succeeded, False otherwise. Training on too few
    events raises, which we catch and log: the daemon does not die just
    because the user has not generated enough behavior yet. Come back when
    you have lived a little.
    """
    store = JsonlStore(config.events_file)
    events = store.read()
    if not events:
        logger.warning("No events to train on. Skipping retrain.")
        return False
    detection = app_config.detection
    features = build_features(app_config)
    model = train_model(events, detection, features=features)
    save_model(model, config.model_file)
    return True


def _monitor_cycle(
    config: DaemonConfig,
    app_config: AppConfig,
    state: DaemonState,
    sink: SiemSink,
) -> tuple[int, int]:
    """Score new events (since last cycle) and ship alerts.

    Returns (events_scored, alerts_sent). Uses byte_offset to read only the
    events appended since the last monitor pass, so we do not re-score the
    entire history every cycle. That would be correct but slow, and slow
    is just wrong with extra steps.

    Alert delivery is isolated per-alert: one alert whose send raises is
    logged and skipped, but the offset still advances past the whole scored
    batch and the remaining alerts still ship. The alternative — aborting the
    cycle and re-sending everything next time — produces duplicate alerts in
    the SIEM, and duplicates are a worse failure mode than one dropped line.
    """
    model_path = config.model_file
    if not model_path.exists():
        # No model yet. This happens on cycle 0 before the first train.
        # Not an error, just early. We will get them next cycle.
        return 0, 0

    model = load_model(model_path)
    events = _read_events_since(config.events_file, state.byte_offset)
    if not events:
        return 0, 0

    detection = app_config.detection
    features = build_features(app_config)
    alerts = detect(events, model, detection, features=features)

    sent = 0
    for alert in alerts:
        try:
            sink.send(alert)
            sent += 1
        except Exception:
            # One alert that fails to ship must not poison the rest of the
            # batch or hold the byte_offset hostage. Log it, skip it, move on.
            logger.exception("Failed to send one alert. Skipping it; remaining alerts still ship.")

    # Advance the offset past everything we just scored, regardless of whether
    # every alert shipped. Re-scoring the same events next cycle would only
    # re-send the alerts that already succeeded.
    state.byte_offset = config.events_file.stat().st_size
    return len(events), sent


def _read_events_since(path: Path, byte_offset: int) -> list[BehaviorEvent]:
    """Read events from a JSONL file starting at byte_offset.

    If the file shrank (rotated, truncated, replaced), we start from zero
    rather than panicking. A file that got smaller is not a bug, it is
    log rotation, and log rotation is a fact of life.
    """
    if not path.exists():
        return []
    current_size = path.stat().st_size
    if current_size < byte_offset:
        # File was rotated or truncated. Start over.
        return JsonlStore(path).read()
    if current_size == byte_offset:
        return []
    events: list[BehaviorEvent] = []
    with path.open(encoding="utf-8") as fh:
        fh.seek(byte_offset)
        for line in fh:
            if line.strip():
                events.append(BehaviorEvent.model_validate_json(line))
    return events


def should_retrain(config: DaemonConfig, state: DaemonState) -> bool:
    """Decide whether this cycle includes a retrain.

    Retrain when training is enabled AND either:
      - it is a scheduled retrain cycle (cycle % every_cycles == 0), or
      - no model file exists yet and monitoring is on (bootstrap case).

    The bootstrap case is the difference between "works on first run" and
    "sits there doing nothing until the admin manually trains a model". We
    prefer the former. The admin has enough to do.
    """
    if not config.train.enabled:
        return False
    is_scheduled = state.cycle % config.train.every_cycles == 0
    needs_bootstrap = config.monitor.enabled and not config.model_file.exists()
    return is_scheduled or needs_bootstrap


def run_cycle(
    app_config: AppConfig,
    state: DaemonState,
    sink: SiemSink | None = None,
) -> CycleResult:
    """Execute one daemon cycle: collect, train, monitor.

    This is the function tests call. It does not loop, does not sleep, does
    not catch signals. It does exactly one cycle and reports what happened.

    sink: optional pre-built SIEM sink. When None (the normal case), the
        sink is built from app_config.siem. Tests can pass a fake sink to
        capture alerts without touching syslog or HTTP.
    """
    config = app_config.daemon
    result = CycleResult(cycle=state.cycle)

    if not config.enabled:
        result.skipped.append("daemon disabled")
        return result

    # Decide whether to retrain based on the cycle we are *about to run*, then
    # increment. Keeping the decision before the increment means the scheduled
    # retrain cadence (cycle % every_cycles == 0) lines up with the cycle
    # number we report, instead of being silently off by one.
    retrain_this_cycle = should_retrain(config, state)
    state.cycle += 1

    # -- Collect ----------------------------------------------------------
    if config.collect.enabled:
        try:
            events = _collect_cycle(config, app_config)
            result.collected = len(events)
        except Exception:
            # A bad collect is a bad cycle, not a dead daemon.
            logger.exception("Collect cycle failed. Will retry next cycle.")
            result.skipped.append("collect failed")
    else:
        result.skipped.append("collect disabled")

    # -- Train ------------------------------------------------------------
    if retrain_this_cycle:
        try:
            result.trained = _train_cycle(config, app_config)
        except Exception:
            logger.exception("Train cycle failed. Will retry next cycle.")
            result.skipped.append("train failed")
    else:
        if config.train.enabled:
            result.skipped.append("train not scheduled this cycle")

    # -- Monitor ----------------------------------------------------------
    if config.monitor.enabled:
        try:
            if sink is None:
                sink = build_sink(app_config.siem)
            scored, alerts = _monitor_cycle(config, app_config, state, sink)
            result.scored = scored
            result.alerts = alerts
        except Exception:
            logger.exception("Monitor cycle failed. Will retry next cycle.")
            result.skipped.append("monitor failed")
    else:
        result.skipped.append("monitor disabled")

    return result


def run_loop(
    app_config: AppConfig,
    stop_event: threading.Event | None = None,
    sink: SiemSink | None = None,
    sleep_func=time.sleep,
) -> None:
    """Run the daemon loop until stop_event is set or the universe ends.

    stop_event: a threading.Event that, when set, tells the loop to exit
        after the current cycle. The CLI wires this to SIGINT/SIGTERM. Tests
        can pass a pre-set event to run zero or one cycles.

    sink: optional pre-built SIEM sink, passed through to run_cycle. Same
        rationale as run_cycle: tests inject fakes, production builds real.
        When None, the sink is built ONCE here (not per cycle) so a webhook
        connection pool is not leaked on every iteration. The sink is closed
        when the loop exits.

    sleep_func: injectable sleep for testing. Real callers leave the default
        (time.sleep). Tests pass a no-op so the loop does not actually wait.
    """
    if stop_event is None:
        stop_event = threading.Event()

    config = app_config.daemon
    if not config.enabled:
        logger.error("Daemon is disabled in config. Nothing to do. Goodbye.")
        return

    interval = config.interval_seconds
    state = DaemonState()

    # Build the sink once for the loop's lifetime. A webhook sink owns an
    # httpx connection pool; rebuilding it per cycle leaks sockets over a
    # long-running daemon. If the sink cannot be built (misconfigured
    # webhook), surface the error once at startup rather than crash-looping
    # silently on every cycle.
    owns_sink = False
    if sink is None and config.monitor.enabled:
        try:
            sink = build_sink(app_config.siem)
            owns_sink = True
        except Exception:
            logger.exception("Could not build the SIEM sink at startup. Alerts will not be shipped.")
            sink = None

    logger.info(
        "Daemon starting: interval=%ds events=%s model=%s",
        interval,
        config.events_file,
        config.model_file,
    )

    try:
        while not stop_event.is_set():
            result = run_cycle(app_config, state, sink=sink)
            _log_cycle(result)
            if stop_event.is_set():
                break
            _interruptible_sleep(interval, stop_event, sleep_func)
    finally:
        if owns_sink and sink is not None and hasattr(sink, "close"):
            try:
                sink.close()
            except Exception:
                logger.exception("Error closing the SIEM sink on shutdown.")

    logger.info("Daemon stopped after %d cycle(s).", state.cycle)


def _log_cycle(result: CycleResult) -> None:
    """Emit a one-line summary of the cycle for the log."""
    parts = [
        f"cycle={result.cycle}",
        f"collected={result.collected}",
        f"trained={result.trained}",
        f"scored={result.scored}",
        f"alerts={result.alerts}",
    ]
    if result.skipped:
        parts.append(f"skipped=[{', '.join(result.skipped)}]")
    logger.info(" | ".join(parts))


def _interruptible_sleep(
    seconds: float,
    stop_event: threading.Event,
    sleep_func=time.sleep,
) -> None:
    """Sleep for `seconds` but wake promptly when stop_event is set.

    We sleep in SLEEP_GRANULARITY chunks and check the flag between each, so
    the user never waits the full interval for Ctrl-C to register. Nobody
    likes a daemon that ignores them, especially the person paying the cloud
    bill.
    """
    remaining = float(seconds)
    while remaining > 0 and not stop_event.is_set():
        chunk = min(remaining, _SLEEP_GRANULARITY_SECONDS)
        sleep_func(chunk)
        remaining -= chunk


def install_signal_handlers(stop_event: threading.Event) -> None:
    """Wire SIGINT and SIGTERM to set the stop event.

    This is the polite way to shut down: the current cycle finishes, the loop
    checks the flag, and we exit cleanly. No half-written files, no orphaned
    model state. The alternative is killing the process mid-cycle and hoping
    for the best, which is not a strategy, it is a prayer.
    """
    def handler(signum, frame):
        logger.info("Received signal %d, shutting down after current cycle.", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
