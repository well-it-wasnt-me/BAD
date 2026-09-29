"""BAD: Behavior Anomaly Detection.

Collect Linux, Windows and macOS telemetry, normalize it, train on what
users normally do, and hand your SIEM a vendor-neutral alert when they stop
doing that. A tool for agents and monitoring stacks, not an agent itself.
The import package stays behavior_anomaly so nobody has to type
`from bad import Alert` with a straight face.
"""

__version__ = "1.2.0"

# Lazy re-exports. Importing this package used to drag in sklearn, numpy and
# joblib eagerly, so even `bad --help` and `bad check-config` paid the full
# ML import cost (over a second of startup). PEP 562 lets us resolve each
# public name on first access instead, so importing a lightweight submodule
# (config, schema) no longer pulls the whole ML stack in behind it.
#
# Each value is (module_path, attribute_name). The heavy chain
# (IsolationForestModel -> sklearn, pipeline -> detection/models) only loads
# when one of those names is actually touched.
_LAZY: dict[str, tuple[str, str]] = {
    "DaemonConfig": ("behavior_anomaly.config", "DaemonConfig"),
    "DetectionConfig": ("behavior_anomaly.config", "DetectionConfig"),
    "SiemConfig": ("behavior_anomaly.config", "SiemConfig"),
    "CycleResult": ("behavior_anomaly.daemon", "CycleResult"),
    "DaemonState": ("behavior_anomaly.daemon", "DaemonState"),
    "run_cycle": ("behavior_anomaly.daemon", "run_cycle"),
    "run_loop": ("behavior_anomaly.daemon", "run_loop"),
    "DetectionEngine": ("behavior_anomaly.detection.engine", "DetectionEngine"),
    "build_windows": ("behavior_anomaly.detection.windowing", "build_windows"),
    "BehavioralFeatures": ("behavior_anomaly.features.behavioral", "BehavioralFeatures"),
    "IsolationForestModel": ("behavior_anomaly.models.isolation_forest", "IsolationForestModel"),
    "detect": ("behavior_anomaly.pipeline", "detect"),
    "monitor": ("behavior_anomaly.pipeline", "monitor"),
    "train_model": ("behavior_anomaly.pipeline", "train_model"),
    "Alert": ("behavior_anomaly.schema", "Alert"),
    "BehaviorEvent": ("behavior_anomaly.schema", "BehaviorEvent"),
    "EventType": ("behavior_anomaly.schema", "EventType"),
    "Platform": ("behavior_anomaly.schema", "Platform"),
    "Severity": ("behavior_anomaly.schema", "Severity"),
    "to_ecs": ("behavior_anomaly.siem.ecs", "to_ecs"),
}

__all__ = list(_LAZY)


def __getattr__(name: str):
    """Resolve lazy re-exports on first access (PEP 562)."""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'behavior_anomaly' has no attribute {name!r}")
    module_path, attr = target
    import importlib

    module = importlib.import_module(module_path)
    value = getattr(module, attr)
    globals()[name] = value  # cache so subsequent lookups skip this hook
    return value


def __dir__() -> list[str]:
    return sorted(__all__ + list(globals()))
