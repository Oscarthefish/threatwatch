from __future__ import annotations

import socket
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    """Isolated data dir, no AI key, no real DNS, no politeness delay."""
    monkeypatch.setenv("TW_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TW_COOKIE_SECURE", "false")
    monkeypatch.setenv("TW_INGEST_MAX_AGE_DAYS", "100000")
    monkeypatch.setenv("TW_QUIET_HOURS", "")  # deterministic regardless of the time tests run
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from app import config
    from app.ingest import fetcher

    config.get_settings.cache_clear()
    monkeypatch.setattr(fetcher, "HOST_MIN_INTERVAL", 0.0)

    real = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *a, **kw):
        if host.endswith((".example", ".example.com", ".example.org")) or host in (
            "www.cisa.gov", "api.first.org", "cveawg.mitre.org", "www.ncsc.govt.nz", "api.ransomware.live"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        if host == "internal.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    yield
    config.get_settings.cache_clear()


@pytest.fixture
def conn():
    from app.db import connect, migrate

    c = connect()
    migrate(c)
    yield c
    c.close()


def fixture_bytes(name: str) -> bytes:
    return (FIX / name).read_bytes()


@pytest.fixture
def fixture_sources(conn, monkeypatch):
    """Replace the default catalogue with two fixture feeds + KEV."""
    from app.ingest import pipeline, sources

    defs = [
        sources.SourceDef("fx-news", "FIXTURE News", "rss", "https://news.example.com/feed", "https://news.example.com/", 2, "GLOBAL", []),
        sources.SourceDef("fx-research", "FIXTURE Research", "rss", "https://research.example.org/atom", "https://research.example.org/", 2, "GLOBAL", ["threat-intel"]),
        sources.SourceDef("fx-kev", "FIXTURE KEV", "kev", "https://www.cisa.gov/kev.json", "https://www.cisa.gov/", 3, "GLOBAL", ["vulnerabilities"]),
    ]
    monkeypatch.setattr(sources, "DEFAULT_SOURCES", defs)
    monkeypatch.setattr(pipeline, "DEFAULT_SOURCES", defs)
    pipeline.sync_sources(conn)
    return defs
