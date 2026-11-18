"""Ransomware leak-site claims: parsing, backfill, rate-limit spacing, the Ransomware API and group profiles.

All claims below are SYNTHETIC: fictitious victims on example domains. Group names are real so name mapping is tested.
"""
from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.db import get_setting, iso, utcnow
from app.ingest import pipeline, ransom

RECENT = "https://api.ransomware.live/v2/recentvictims"
MONTH = "https://api.ransomware.live/v2/victims/"
H = {"X-TW-Request": "1"}


def claim(victim, group, days_ago=1, country="US", sector="Manufacturing", domain="victim.example", n=None):
    d = iso(utcnow() - timedelta(days=days_ago))
    rid = f"{victim}@{group}@{n if n is not None else days_ago}"
    return {"victim": victim, "group": group, "country": country, "activity": sector, "domain": domain,
            "discovered": d, "attackdate": d, "url": f"https://www.ransomware.live/id/{rid.replace(' ', '_')}",
            "description": "SYNTHETIC leak description that must never be stored", "screenshot": "x.png",
            "claim_url": "/p/abc"}


def test_parse_validates_and_normalises():
    rows = ransom.parse(json.dumps([
        claim("Contoso &amp; Sons", "thegentlemen", country="nz", sector="Not Found", domain="Contoso.example"),
        claim("Fabrikam", "lockbit5", domain="not a domain"),
        claim("Tailspin", "medusalocker"), claim("Northwind", "clop"), claim("Woodgrove", "incransom"),
        claim("Litware", "vortex"),
        {"victim": "No URL", "group": "qilin", "discovered": iso(utcnow())},
        {"victim": "Wrong host", "group": "qilin", "discovered": iso(utcnow()), "url": "http://leaksite.example/x"},
        {"victim": "", "group": "qilin", "discovered": iso(utcnow()), "url": "https://www.ransomware.live/id/a"},
        "not an object",
    ]).encode())
    by = {r["victim"]: r for r in rows}
    assert set(by) == {"Contoso & Sons", "Fabrikam", "Tailspin", "Northwind", "Woodgrove", "Litware"}
    c = by["Contoso & Sons"]
    assert c["group_name"] == "The Gentlemen" and c["group_raw"] == "thegentlemen"
    assert c["country"] == "NZ" and c["sector"] is None and c["domain"] == "contoso.example"
    assert by["Fabrikam"]["group_name"] == "LockBit" and by["Fabrikam"]["domain"] is None
    assert by["Tailspin"]["group_name"] == "MedusaLocker"  # a separate family, not Medusa
    assert by["Northwind"]["group_name"] == "Cl0p" and by["Woodgrove"]["group_name"] == "INC Ransom"
    assert by["Litware"]["group_name"] == "Vortex"
    assert all("description" not in r and "screenshot" not in r for r in rows)
    with pytest.raises(ValueError):
        ransom.parse(b'{"error": "rate limited"}')


@pytest.fixture
def src(conn):
    pipeline.sync_sources(conn)
    return pipeline._source_dict(conn.execute("SELECT * FROM sources WHERE key='ransomware-live'").fetchone())


@respx.mock
def test_backfill_once_with_rate_limit_spacing(conn, src):
    respx.get(RECENT).mock(return_value=httpx.Response(200, json=[claim("Contoso", "qilin", 1), claim("Fabrikam", "akira", 2)]))
    month = respx.get(url__startswith=MONTH).mock(return_value=httpx.Response(200, json=[claim("Contoso", "qilin", 1), claim("Old Co", "play", 50)]))
    sleeps = []
    n, detail = ransom.ingest_claims(conn, src, sleep=sleeps.append)
    assert month.call_count == 3 and sleeps == [61, 61, 61]  # never more than one request a minute per endpoint
    assert n == 3 and "backfill" in detail
    assert get_setting(conn, "ransom_claims_since") and get_setting(conn, "ransom_claims_backfilled")
    sleeps.clear()
    n, _ = ransom.ingest_claims(conn, src, sleep=sleeps.append)
    assert n == 0 and sleeps == [] and month.call_count == 3  # backfill runs once; duplicates ignored
    assert conn.execute("SELECT COUNT(*) FROM ransomware_claims").fetchone()[0] == 3


@respx.mock
def test_failed_backfill_month_retried_next_run(conn, src):
    respx.get(RECENT).mock(return_value=httpx.Response(200, json=[claim("Contoso", "qilin", 1)]))
    respx.get(url__startswith=MONTH).mock(return_value=httpx.Response(429))
    n, detail = ransom.ingest_claims(conn, src, sleep=lambda s: None)
    assert n == 1 and "retrying" in detail and not get_setting(conn, "ransom_claims_backfilled")


@respx.mock
def test_tracker_failure_isolated_in_run(conn):
    pipeline.sync_sources(conn)
    conn.execute("UPDATE sources SET enabled=0 WHERE key NOT IN ('ransomware-live')")
    respx.get(RECENT).mock(return_value=httpx.Response(503))
    r = pipeline.run_ingest(conn, force=True)
    assert r["sources"]["ransomware-live"].startswith("error")
    assert conn.execute("SELECT consecutive_failures FROM sources WHERE key='ransomware-live'").fetchone()[0] == 1


@pytest.fixture
def client(conn):
    from app.auth import hash_password
    from app.main import create_app
    conn.execute("INSERT INTO users(username, password_hash) VALUES('analyst', ?)", (hash_password("correct horse battery staple"),))
    c = TestClient(create_app())
    assert c.post("/api/auth/login", json={"username": "analyst", "password": "correct horse battery staple"}).status_code == 200
    return c


def _seed(conn):
    rows = []
    for i in range(10):
        rows.append(claim(f"Qilin victim {i}", "qilin", 1 + i, n=i, sector="Healthcare" if i % 2 else "Manufacturing"))
    for i in range(6):
        rows.append(claim(f"Gent victim {i}", "thegentlemen", 2 + i, n=i, country="DE"))
    for i in range(8):
        rows.append(claim(f"Old Akira victim {i}", "akira", 35 + i, n=i))  # previous period only: falling
    rows.append(claim("Contoso Health", "thegentlemen", 3, country="NZ", sector="Healthcare", n=99))
    rows.append(claim("Bank", "vortex", 4, country="AU", n=98))  # generic name: never linked to news
    ransom.store(conn, ransom.parse(json.dumps(rows).encode()))
    conn.execute("INSERT INTO settings(key, value) VALUES('ransom_claims_since', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (json.dumps((utcnow() - timedelta(days=95)).date().isoformat()),))
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    when = iso(utcnow() - timedelta(days=2))
    conn.execute("INSERT INTO articles(source_id,url,canonical_url,title,summary_text,retrieved_at,published_at) VALUES(?,?,?,?,?,?,?)",
                 (src, "https://news.example.com/contoso", "https://news.example.com/contoso", "Contoso Health confirms cyberattack disrupted clinics",
                  "The New Zealand provider is investigating.", when, when))


def test_ransomware_page_data(client, conn):
    pipeline.sync_sources(conn)
    _seed(conn)
    d = client.get("/api/ransomware?days=30").json()
    assert d["totals"]["current"] == 18 and d["totals"]["previous"] == 8 and not d["comparison_indicative"]
    names = [g["name"] for g in d["groups"]]
    assert names[:2] == ["Qilin", "The Gentlemen"]
    q = d["groups"][0]
    assert q["cur"] == 10 and q["tracker_url"] == "https://www.ransomware.live/group/qilin"
    assert {s["name"] for s in q["sectors"]} == {"Healthcare", "Manufacturing"}
    assert "Akira" in [m["name"] for m in d["falling"]] and "Qilin" in [m["name"] for m in d["rising"]]
    assert [c["victim"] for c in d["regional"]] == ["Contoso Health", "Bank"]
    contoso = d["regional"][0]
    assert contoso["news"] and contoso["news"][0]["title"].startswith("Contoso Health")
    assert d["regional"][1]["news"] == []
    assert all(c["record_url"].startswith("https://www.ransomware.live/id/") for c in d["recent"])
    assert all("description" not in c for c in d["recent"])
    assert sum(v["count"] for v in d["volume"]) == 18


def test_group_profiles_include_claims(client, conn):
    pipeline.sync_sources(conn)
    _seed(conn)
    g = client.get("/api/groups/ransomware/Qilin").json()
    assert g["claims"]["current"] == 10 and len(g["claims"]["recent"]) == 10
    # a group known only from leak-site claims still has a profile
    v = client.get("/api/groups/ransomware/vortex")
    assert v.status_code == 200 and v.json()["name"] == "Vortex" and v.json()["claims"]["current"] == 1
    assert client.get("/api/groups/ransomware/Nonexistent Crew").status_code == 404
    assert client.get("/api/groups/actor/Turla").json().get("claims") is None


def test_requires_auth(conn):
    from app.main import create_app
    assert TestClient(create_app()).get("/api/ransomware").status_code == 401
