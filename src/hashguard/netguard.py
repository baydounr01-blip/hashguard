"""Outbound request guard.

The agent lives inside the farm network, which is exactly the position an
attacker would like to borrow. HashGuard v1 let the console write an arbitrary
``price_url`` and arbitrary webhook URLs into the agent's config, and the agent
would fetch them. That turns the console token into a request-forgery primitive
aimed at the farm's own LAN, at the router's admin page, and at cloud metadata
services on 169.254.169.254.

This module makes the two kinds of outbound request the agent legitimately
needs, and refuses everything else. The policies are deliberately opposite:

* :func:`fetch_public_json` -- for market and price data. **HTTPS only**, and
  the hostname must resolve to a *public* address. Anything that resolves into
  private, loopback, link-local, or reserved space is refused: a price feed has
  no business being inside the farm.
* :func:`call_local_webhook` -- for smart plugs and relays. **Private
  addresses only**, and only hosts the operator put in an explicit allowlist. A
  relay control URL has no business being on the public internet.

Both pin the address they vetted and connect to *that*, so a name that resolves
public on the check and private on the connect -- DNS rebinding -- does not get
a second answer. Redirects are never followed; a 302 is a server asking to
change the destination after the destination was approved. Responses are read
under a byte cap, so a hostile or broken endpoint cannot exhaust memory.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlparse

#: Nothing the agent legitimately fetches is larger than this.
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT = 8.0


class NetGuardError(RuntimeError):
    """The request was refused before a single packet left the machine."""


def _resolve(host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise NetGuardError(f"cannot resolve {host!r}: {exc}") from exc
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addresses:
        raise NetGuardError(f"{host!r} resolved to no usable address")
    return addresses


def is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Public in the sense that matters here: not somewhere we could pivot to."""
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-vetted IP, with the certificate still checked against the
    real hostname. The vetting and the connection therefore cannot disagree."""

    def __init__(self, host: str, pinned_ip: str, **kwargs) -> None:
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # pragma: no cover - exercised only against a live host
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _read_capped(response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise NetGuardError(f"response exceeds {limit} bytes; refusing to buffer it")
    return body


def fetch_public_json(url: str, headers: dict | None = None, timeout: float = DEFAULT_TIMEOUT):
    """GET a JSON document from the public internet, or refuse and say why."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise NetGuardError(
            f"price sources must be https, got {parsed.scheme or 'no scheme'!r}: "
            "an hourly price fetched over plaintext is an hourly price anyone on "
            "the path can choose for you"
        )
    if not parsed.hostname:
        raise NetGuardError(f"no host in {url!r}")
    port = parsed.port or 443
    addresses = _resolve(parsed.hostname, port)
    private = [a for a in addresses if not is_public(a)]
    if private:
        raise NetGuardError(
            f"{parsed.hostname} resolves to {private[0]}, which is inside private or "
            "reserved address space. A price feed is not allowed to point back into "
            "your network."
        )
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    connection = _PinnedHTTPSConnection(
        parsed.hostname, str(addresses[0]), port=port, timeout=timeout, context=context
    )
    try:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request("GET", path, headers={"Accept": "application/json", **(headers or {})})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise NetGuardError(
                f"{url} answered {response.status}; redirects are not followed, because a "
                "redirect changes the destination after it was vetted"
            )
        if response.status != 200:
            raise NetGuardError(f"{url} answered HTTP {response.status}")
        body = _read_capped(response)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise NetGuardError(f"request to {parsed.hostname} failed: {exc}") from exc
    finally:
        connection.close()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise NetGuardError(f"{url} did not return JSON: {exc}") from exc


def validate_webhook(url: str, allowlist: list[str]) -> tuple[str, int, str]:
    """Check a relay-control URL against the operator's allowlist.

    Returns ``(host, port, path)``. Raises unless the URL is http(s) to a host
    that is both *in the allowlist* and *on a private address*.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NetGuardError(f"webhook scheme must be http or https, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise NetGuardError(f"no host in webhook {url!r}")
    if parsed.hostname not in allowlist:
        raise NetGuardError(
            f"{parsed.hostname} is not in curtailment.webhook_allowlist. Add it there "
            "deliberately; the agent will not call a host nobody listed."
        )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for address in _resolve(parsed.hostname, port):
        if is_public(address):
            raise NetGuardError(
                f"{parsed.hostname} resolves to the public address {address}. Relay "
                "control is a local-network action; it will not be sent to the internet."
            )
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, port, path


def call_local_webhook(url: str, allowlist: list[str], timeout: float = 5.0) -> int:
    """Fire a vetted relay webhook. Returns the HTTP status."""
    host, port, path = validate_webhook(url, allowlist)
    address = str(_resolve(host, port)[0])
    scheme = urlparse(url).scheme
    if scheme == "https":
        context = ssl.create_default_context()
        connection = _PinnedHTTPSConnection(host, address, port=port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(address, port=port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Host": host})
        response = connection.getresponse()
        _read_capped(response, 64 * 1024)
        return response.status
    except (OSError, http.client.HTTPException) as exc:
        raise NetGuardError(f"webhook {host} failed: {exc}") from exc
    finally:
        connection.close()
