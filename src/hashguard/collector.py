"""Talking to the miners, without trusting them.

The agent's job puts it downstream of hardware it does not control: Antminers,
Whatsminers and Braiins boxes running vendor firmware of varying vintage,
reachable on TCP 4028 with no authentication whatsoever. Anything that can
reach that port can answer for a miner.

HashGuard v1 read that socket with ``while True: buf += s.recv(4096)`` and no
cap. A miner that never stops talking -- broken, or replaced by something
hostile that got onto the LAN -- fills the agent's memory until it dies, and an
agent that dies stops measuring the savings the client is being billed for.

So every read here is bounded: a byte cap, a wall-clock deadline, and a limit
on how many boards a single response is allowed to declare. Parsing stays
defensive, because firmware field names genuinely do vary and a missing key is
normal operation, not an attack.
"""

from __future__ import annotations

import json
import math
import random
import socket
import time

#: A ``stats`` response from a healthy miner is a few kilobytes.
MAX_RESPONSE_BYTES = 256 * 1024
MAX_BOARDS = 16
MAX_FANS = 16
DEFAULT_TIMEOUT = 5.0


class CollectorError(RuntimeError):
    """The miner could not be read. Never fatal: a silent miner is a data gap."""


def cgminer_command(host: str, port: int, command: str, timeout: float = DEFAULT_TIMEOUT) -> dict | None:
    """Send one cgminer API command and parse the reply, under hard limits.

    Returns ``None`` on any failure. A miner that will not answer is a fact
    about the farm to be reported, not an exception to propagate into the poll
    loop and stop the other miners from being read.
    """
    deadline = time.monotonic() + timeout
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(json.dumps({"command": command}).encode("ascii"))
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectorError(f"{host}:{port} exceeded its {timeout}s budget")
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise CollectorError(
                    f"{host}:{port} sent more than {MAX_RESPONSE_BYTES} bytes; "
                    "a stats reply is a few kilobytes, so this is not a miner behaving"
                )
            chunks.append(chunk)
        payload = b"".join(chunks).replace(b"\x00", b"")
        return json.loads(payload.decode("utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, CollectorError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _as_float(value) -> float | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def parse_stats(raw: dict | None) -> dict | None:
    """Per-hashboard hashrate, temperature, fan RPM and hardware errors.

    Field names differ between firmwares, so every lookup is a try-and-shrug.
    The bounds are the part that is not negotiable: a response declaring 4000
    hashboards is not a large farm, it is a malformed or hostile reply.
    """
    if not raw or "STATS" not in raw or not isinstance(raw["STATS"], list):
        return None
    boards: list[dict] = []
    fans: list[float] = []
    hardware_errors = 0

    for entry in raw["STATS"]:
        if not isinstance(entry, dict):
            continue
        for index in range(1, MAX_BOARDS + 1):
            rate = _as_float(entry.get(f"chain_rate{index}"))
            if rate is None or rate <= 0:
                continue
            temperatures: list[float] = []
            for key in (f"temp{index}", f"temp2_{index}", f"temp_chip{index}", f"temp_pcb{index}"):
                value = entry.get(key)
                if value in (None, "", 0):
                    continue
                for part in str(value).replace(" ", "").split("-"):
                    temperature = _as_float(part)
                    if temperature is not None and -50 < temperature < 200:
                        temperatures.append(temperature)
            boards.append(
                {
                    "idx": index,
                    "hashrate_gh": rate,
                    "temp_max": max(temperatures) if temperatures else None,
                    "temp_spread": (max(temperatures) - min(temperatures)) if len(temperatures) > 1 else None,
                }
            )
            if len(boards) >= MAX_BOARDS:
                break
        for index in range(1, MAX_FANS + 1):
            rpm = _as_float(entry.get(f"fan{index}"))
            if rpm is not None and 0 < rpm < 30000:
                fans.append(rpm)
        for key in ("Hardware Errors", "hw_errors", "HW"):
            value = _as_float(entry.get(key))
            if value is not None and 0 <= value < 1e12:
                hardware_errors = max(hardware_errors, int(value))

    if not boards:
        return None
    return {"boards": boards, "fans": fans[:MAX_FANS], "hw_errors": hardware_errors}


class SimulatedFarm:
    """A farm that exists only in the process, for ``--demo``.

    It has one board degrading slowly and one fan compensating for a blocked
    intake, so the demo shows the engine finding something real rather than a
    wall of green.
    """

    def __init__(self, miners: int = 6, boards_per_miner: int = 3, seed: int = 7) -> None:
        self.random = random.Random(seed)
        self.miners = miners
        self.boards_per_miner = boards_per_miner
        self.tick = 0
        self.base_hashrate = 35000.0  # GH/s per board, ~105 TH per machine

    def read(self, miner_index: int) -> dict:
        self.tick += 1
        ambient = 28 + 4 * math.sin(self.tick / 40)
        boards = []
        for board in range(self.boards_per_miner):
            hashrate = self.base_hashrate * (1 + self.random.gauss(0, 0.012))
            if miner_index == 4 and board == 2:
                hashrate *= 1 - 0.00025 * self.tick
            boards.append(
                {
                    "idx": board + 1,
                    "hashrate_gh": hashrate,
                    "temp_max": ambient + 32 + self.random.gauss(0, 1.5),
                    "temp_spread": abs(self.random.gauss(4, 1)),
                }
            )
        fans = []
        for fan in range(4):
            rpm = 4200 + (ambient - 28) * 60 + self.random.gauss(0, 80)
            if miner_index == 2 and fan == 1:
                rpm += 1.8 * self.tick
            fans.append(rpm)
        return {"boards": boards, "fans": fans, "hw_errors": max(0, int(self.random.gauss(2, 1)))}
