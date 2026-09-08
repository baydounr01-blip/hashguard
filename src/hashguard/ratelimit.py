"""Progressive rate limiting for the agent's API.

Ported from ``PersistentAccessLimiter`` in the quantumbot547 repository
(``netlify/functions/_lib/access-rate-limit.mts``), which guards that project's
client access endpoint. The shape is the same and so is the reasoning:

* a **window cap** stops a burst,
* a **failure counter** notices that the bursts are all wrong guesses,
* and the block that follows **doubles** each time, so an attacker who keeps
  guessing spends exponentially longer waiting, while an operator who fat-fingers
  their token once waits a second.

HashGuard v1 had none of this. Its token check was a single
``compare_digest`` with no cost attached to being wrong, so a 24-byte token was
only as strong as the attacker's patience on a LAN that can carry tens of
thousands of requests a second.

Keys are the identifiers a single request touches -- typically the client IP and
the presented token's fingerprint. Every key is counted, and the *strictest*
answer wins, so an attacker rotating one dimension is still caught on the other.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Decision:
    allowed: bool
    retry_after: int = 0     # whole seconds, for the Retry-After header
    reason: str = ""


@dataclass
class _Record:
    window_start: float = 0.0
    attempts: int = 0
    failures: int = 0
    blocked_until: float = 0.0


@dataclass
class RateLimiter:
    """Thread-safe, in-memory, monotonic-clock limiter."""

    window_s: float = 60.0
    max_attempts: int = 60
    failure_threshold: int = 5
    base_block_s: float = 2.0
    max_block_s: float = 900.0
    clock: callable = time.monotonic
    _records: dict[str, _Record] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _record(self, key: str) -> _Record:
        record = self._records.get(key)
        if record is None:
            record = _Record(window_start=self.clock())
            self._records[key] = record
        return record

    def consume(self, keys: list[str]) -> Decision:
        """Count one request against every key. Strictest answer wins."""
        now = self.clock()
        with self._lock:
            self._evict(now)
            worst: Decision | None = None
            for key in keys:
                record = self._record(key)
                if record.blocked_until > now:
                    decision = Decision(
                        False,
                        max(1, int(record.blocked_until - now + 0.999)),
                        "temporarily blocked after repeated failures",
                    )
                elif now - record.window_start >= self.window_s:
                    record.window_start = now
                    record.attempts = 1
                    decision = Decision(True)
                elif record.attempts >= self.max_attempts:
                    decision = Decision(
                        False,
                        max(1, int(self.window_s - (now - record.window_start) + 0.999)),
                        "request rate exceeded",
                    )
                else:
                    record.attempts += 1
                    decision = Decision(True)
                if not decision.allowed and (worst is None or decision.retry_after > worst.retry_after):
                    worst = decision
            return worst or Decision(True)

    def failed(self, keys: list[str]) -> float:
        """Register an authentication failure. Returns the block imposed, in seconds."""
        now = self.clock()
        with self._lock:
            longest = 0.0
            for key in keys:
                record = self._record(key)
                record.failures += 1
                if record.failures >= self.failure_threshold:
                    over = record.failures - self.failure_threshold
                    block = min(self.max_block_s, self.base_block_s * (2 ** over))
                    record.blocked_until = max(record.blocked_until, now + block)
                    longest = max(longest, block)
            return longest

    def succeeded(self, keys: list[str]) -> None:
        """A valid credential clears the suspicion it was accumulating."""
        with self._lock:
            for key in keys:
                record = self._records.get(key)
                if record is not None:
                    record.failures = 0
                    record.blocked_until = 0.0

    def _evict(self, now: float) -> None:
        """Drop records that are idle and unblocked, so the table cannot grow
        without bound from spoofed source addresses."""
        if len(self._records) < 4096:
            return
        stale = [
            key
            for key, record in self._records.items()
            if record.blocked_until <= now and now - record.window_start > self.window_s * 4
        ]
        for key in stale:
            del self._records[key]
