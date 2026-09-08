"""Append-only JSONL logs, with a size ceiling.

The logs are the training set for whatever prediction layer eventually replaces
the hand-tuned thresholds, so they are worth keeping. They are also written
every minute forever on a machine that may be a Raspberry Pi with an 8 GB card,
so they are worth bounding. v1 wrote without limit; a year of six miners fills
the card and the agent stops -- which stops the measurement the client is billed
on.

The rule here: rotate daily, and when the directory passes its ceiling, delete
the oldest days until it fits. Old telemetry is the least valuable thing on the
disk; the ledger is never touched by this and never rotated.
"""

from __future__ import annotations

import json
import os
from datetime import date


def append(log_dir: str, payload: dict, max_mb: int = 256) -> None:
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{date.today().isoformat()}.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except OSError as exc:  # pragma: no cover
        print(f"[logs] cannot write {path}: {exc}")
        return
    _enforce_ceiling(log_dir, max_mb)


def _enforce_ceiling(log_dir: str, max_mb: int) -> None:
    try:
        files = sorted(
            (f for f in os.listdir(log_dir) if f.endswith(".jsonl")),
        )
        total = sum(os.path.getsize(os.path.join(log_dir, f)) for f in files)
        ceiling = max_mb * 1024 * 1024
        while total > ceiling and len(files) > 1:
            oldest = files.pop(0)
            path = os.path.join(log_dir, oldest)
            total -= os.path.getsize(path)
            os.remove(path)
            print(f"[logs] rotated out {oldest} to stay under {max_mb} MB")
    except OSError:  # pragma: no cover
        pass
