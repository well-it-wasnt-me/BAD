"""Model persistence. Save to disk, load from disk, go home.

joblib handles the numpy internals so we do not have to think about them.
Fair warning for the future: joblib files are pickles, and pickles execute
code on load. Only load models you built yourself, like only taking candy
from strangers you have known for years.

To make that warning worth something, this module supports an optional HMAC
signature: when a shared secret is provided, `save_model` writes a sibling
`<path>.sig` file and `load_model` verifies it before unpickling. A swapped
or tampered model file fails the check instead of running arbitrary code as
the daemon user. Without a secret the behavior is unchanged (a model is
still a pickle; treat the directory as root-owned).
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import joblib

from behavior_anomaly.models.base import AnomalyModel


def save_model(
    model: AnomalyModel,
    path: str | Path,
    *,
    secret: bytes | str | None = None,
) -> None:
    """Serialize a trained model to disk, creating parent folders as needed.

    When `secret` is given, an HMAC-SHA256 of the serialized bytes is written
    next to the model so `load_model` can detect tampering or swap. The model
    directory is created with restrictive 0o700 permissions because a model
    file is a code-execution vector, not a community resource.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.parent.chmod(0o700)
    except (OSError, NotImplementedError, PermissionError):
        # chmod is best-effort: on Windows it is a no-op-ish, and we may not
        # own the dir in a managed deployment. We do not let it block a save.
        pass
    joblib.dump(model, target)
    if secret is not None:
        key = _as_bytes(secret)
        digest = hmac.new(key, target.read_bytes(), hashlib.sha256).hexdigest()
        Path(str(target) + ".sig").write_text(digest, encoding="utf-8")


def load_model(path: str | Path, *, secret: bytes | str | None = None) -> AnomalyModel:
    """Load a model back from disk and hand it over as its interface.

    When `secret` is given and a sibling `.sig` file exists, the model bytes
    are verified against the HMAC before unpickling. A missing signature file
    with a secret provided, or a mismatched digest, raises — refusing to load
    is the only safe answer for a code-execution vector we cannot trust.
    """
    target = Path(path)
    if secret is not None:
        sig_path = Path(str(target) + ".sig")
        if not sig_path.exists():
            raise ValueError(
                f"Model signature missing for {target}. Refusing to load an "
                "unverified model when a secret is configured."
            )
        key = _as_bytes(secret)
        expected = hmac.new(key, target.read_bytes(), hashlib.sha256).hexdigest()
        actual = sig_path.read_text(encoding="utf-8").strip()
        if not hmac.compare_digest(expected, actual):
            raise ValueError(
                f"Model signature mismatch for {target}. The model file may have "
                "been tampered with or swapped. Refusing to unpickle."
            )
    return joblib.load(target)


def _as_bytes(secret: bytes | str) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else secret
