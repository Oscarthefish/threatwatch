"""Hardened outbound HTTP fetching.

Protections against unsafe URL fetching (SSRF) and hostile responses:
- only http/https on ports 80/443 (plus explicit allow for tests)
- hostnames are resolved and every address must be public (no loopback,
  private, link-local, CGNAT, multicast or reserved ranges)
- redirects are followed manually and each hop is re-validated
- response bodies are streamed with a hard size cap
- per-host politeness delay and bounded retries with backoff

Residual risk: DNS rebinding between validation and connect. Sources can only be
added by the authenticated owner, which keeps this acceptable for a single-user tool.
"""
from __future__ import annotations

from typing import BinaryIO

import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import get_settings

log = logging.getLogger(__name__)

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5
_host_last: dict[str, float] = {}
_host_lock = threading.Lock()
HOST_MIN_INTERVAL = 1.0  # seconds between requests to the same host


class FetchError(Exception):
    pass


class UnsafeURLError(FetchError):
    pass


@dataclass
class FetchResult:
    url: str
    status: int
    content: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    def text(self) -> str:
        ct = self.headers.get("content-type", "")
        enc = "utf-8"
        if "charset=" in ct:
            enc = ct.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.content.decode(enc, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")


def _is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"))
    )


def validate_url(url: str, resolve: bool = True) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme not allowed: {parts.scheme!r}")
    if not parts.hostname:
        raise UnsafeURLError("missing host")
    if parts.username or parts.password:
        raise UnsafeURLError("credentials in URL not allowed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(f"port not allowed: {port}")
    host = parts.hostname
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        if not _is_public_ip(host):
            raise UnsafeURLError("non-public address")
    elif resolve:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise FetchError(f"DNS resolution failed for {host}: {e}") from e
        addrs = {i[4][0] for i in infos}
        if not addrs or not all(_is_public_ip(a) for a in addrs):
            raise UnsafeURLError(f"host {host} resolves to a non-public address")
    return url


def _polite_wait(host: str) -> None:
    with _host_lock:
        last = _host_last.get(host, 0.0)
        wait = HOST_MIN_INTERVAL - (time.monotonic() - last)
        _host_last[host] = time.monotonic() + max(wait, 0)
    if wait > 0:
        time.sleep(wait)


def fetch(
    url: str,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    accept: str = "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json, text/html;q=0.8, */*;q=0.5",
    max_bytes: int | None = None,
    retries: int = 2,
    client: httpx.Client | None = None,
    resolve: bool = True,
    sink: BinaryIO | None = None,
) -> FetchResult:
    """Fetch a public URL. With ``sink`` the body is streamed to that file instead of held in memory."""
    s = get_settings()
    cap = max_bytes or s.http_max_bytes
    headers = {"User-Agent": s.user_agent, "Accept": accept, "Accept-Encoding": "gzip, deflate"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    own = client is None
    c = client or httpx.Client(timeout=s.http_timeout_seconds, follow_redirects=False)
    try:
        attempt = 0
        while True:
            try:
                if sink is not None:
                    sink.seek(0)
                    sink.truncate()
                return _fetch_once(c, url, headers, cap, resolve, sink)
            except (httpx.TransportError, _Retryable) as e:
                attempt += 1
                if attempt > retries:
                    raise FetchError(f"{type(e).__name__}: {e}") from e
                time.sleep(min(2 ** attempt, 10))
    finally:
        if own:
            c.close()


class _Retryable(Exception):
    pass


def _fetch_once(c: httpx.Client, url: str, headers: dict, cap: int, resolve: bool, sink: BinaryIO | None = None) -> FetchResult:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current, resolve=resolve)
        _polite_wait(urlsplit(current).hostname or "")
        with c.stream("GET", current, headers=headers) as r:
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location")
                if not loc:
                    raise FetchError("redirect without location")
                current = urljoin(current, loc)
                continue
            if r.status_code == 304:
                return FetchResult(url=current, status=304, headers=dict(r.headers))
            if r.status_code == 429 or r.status_code >= 500:
                raise _Retryable(f"HTTP {r.status_code}")
            if r.status_code >= 400:
                raise FetchError(f"HTTP {r.status_code}")
            declared = r.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > cap:
                raise FetchError(f"response too large ({declared} bytes)")
            buf = bytearray()
            size = 0
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > cap:
                    raise FetchError(f"response exceeded {cap} bytes")
                if sink is not None:
                    sink.write(chunk)
                else:
                    buf.extend(chunk)
            return FetchResult(url=current, status=r.status_code, content=bytes(buf), headers={k.lower(): v for k, v in r.headers.items()})
    raise FetchError("too many redirects")
