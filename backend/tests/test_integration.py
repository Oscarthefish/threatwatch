"""Integration tests: ingestion pipeline, Threat Watch engine, API auth and flows, mocked AI."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.db import jloads
from app.ingest import pipeline
from app.intel import ai, briefing, watch
from tests.conftest import fixture_bytes


def mock_feeds(kev="kev.json"):
    respx.get("https://news.example.com/feed").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_news.xml"), headers={"etag": '"n1"'}))
    respx.get("https://research.example.org/atom").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_research.xml")))
    respx.get("https://www.cisa.gov/kev.json").mock(return_value=httpx.Response(200, content=fixture_bytes(kev)))


@respx.mock
def test_ingest_dedupe_and_clusters(conn, fixture_sources):
    mock_feeds()
    r1 = pipeline.run_ingest(conn, force=True)
    for aid in r1["new_articles"]:
        pipeline.process_article(conn, aid)
    assert len(r1["new_articles"]) == 6
    # tracking params stripped, original URL preserved
    row = conn.execute("SELECT url, canonical_url, retrieved_at, published_at FROM articles WHERE guid='news-1'").fetchone()
    assert "utm_source" in row["url"] and "utm_source" not in row["canonical_url"]
    assert row["retrieved_at"] and row["published_at"]
    # script removed from untrusted content
    assert "alert(1)" not in conn.execute("SELECT summary_text FROM articles WHERE guid='news-1'").fetchone()[0]
    # second run: nothing new (exact dedupe)
    r2 = pipeline.run_ingest(conn, force=True)
    assert r2["new_articles"] == []
    # the two CVE-2099-0001 reports cluster; the two different Akira victims do not
    a = conn.execute("SELECT cluster_id FROM articles WHERE guid='news-1'").fetchone()[0]
    b = conn.execute("SELECT cluster_id FROM articles WHERE guid='res-1'").fetchone()[0]
    assert a == b
    c1 = conn.execute("SELECT cluster_id FROM articles WHERE guid='news-2'").fetchone()[0]
    c2 = conn.execute("SELECT cluster_id FROM articles WHERE guid='news-3'").fetchone()[0]
    assert c1 != c2
    assert conn.execute("SELECT confidence FROM articles WHERE guid='res-1'").fetchone()[0] == "multi-source"
    # KEV loaded; IOC + region extraction
    assert conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev=1").fetchone()[0] == 2
    ents = pipeline.article_entities(conn, conn.execute("SELECT id FROM articles WHERE guid='news-2'").fetchone()[0])
    assert "203.0.113.77" not in ents.get("ipv4", set())  # documentation range is not global → not an IOC
    assert "evil-c2.example" in ents.get("domain", set())
    assert "nz" in ents.get("region", set())


@respx.mock
def test_kev_new_additions_detected(conn, fixture_sources):
    mock_feeds()
    pipeline.run_ingest(conn, force=True, only=["fx-kev"])
    respx.reset()
    mock_feeds("kev_v2.json")
    r = pipeline.run_ingest(conn, force=True, only=["fx-kev"])
    assert r["new_kev"] == ["CVE-2099-0001"]


@respx.mock
def test_source_failure_isolated(conn, fixture_sources):
    respx.get("https://news.example.com/feed").mock(return_value=httpx.Response(500))
    respx.get("https://research.example.org/atom").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_research.xml")))
    respx.get("https://www.cisa.gov/kev.json").mock(return_value=httpx.Response(200, content=fixture_bytes("kev.json")))
    r = pipeline.run_ingest(conn, force=True)
    assert r["sources"]["fx-news"].startswith("error")
    assert len(r["new_articles"]) == 2
    assert conn.execute("SELECT consecutive_failures FROM sources WHERE key='fx-news'").fetchone()[0] == 1


@respx.mock
def test_ncsc_adapter():
    from app.ingest.sources import NcscNzAdapter

    respx.get("https://www.ncsc.govt.nz/alerts/").mock(return_value=httpx.Response(200, content=fixture_bytes("ncsc_alerts.html"), headers={"content-type": "text/html"}))
    respx.get("https://www.ncsc.govt.nz/alerts/cve-2099-0004-affecting-example-gateway/").mock(
        return_value=httpx.Response(200, content=fixture_bytes("ncsc_detail.html"), headers={"content-type": "text/html"}))
    res = NcscNzAdapter().run({"url": "https://www.ncsc.govt.nz/alerts/"})
    assert len(res.items) == 1
    it = res.items[0]
    assert it.title == "CVE-2099-0004 affecting Example Gateway"
    assert it.summary_text.startswith("FIXTURE")
    assert it.published_at.isoformat().startswith("2026-11-04T21:00")


def _ingest_split(conn):
    """Ingest the news feed first, then the research feed (simulating later reporting)."""
    respx.get("https://news.example.com/feed").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_news.xml")))
    respx.get("https://www.cisa.gov/kev.json").mock(return_value=httpx.Response(200, content=fixture_bytes("kev_v2.json")))
    r = pipeline.run_ingest(conn, force=True, only=["fx-news", "fx-kev"])
    return r


@respx.mock
def test_watch_lifecycle_incident_not_merged(conn, fixture_sources):
    _ingest_split(conn)
    origin = conn.execute("SELECT id FROM articles WHERE guid='news-2'").fetchone()[0]
    wid, created = watch.create_watch(conn, kind="incident", title="Contoso Health ransomware attack",
                                      identifiers=["Contoso Health"], context_terms=["Akira"], origin_article_id=origin,
                                      notify_pref="all")
    assert created
    linked = {r[0] for r in conn.execute("SELECT a.guid FROM watch_evidence we JOIN articles a ON a.id=we.article_id WHERE we.watch_id=? AND we.status='linked'", (wid,))}
    assert linked == {"news-2"}  # Fabrikam (same actor, different victim) NOT merged
    rec1 = watch.latest_summary(conn, wid)
    assert rec1["version"] == 1 and rec1["method"] == "heuristic"
    assert any(i["value"] == "evil-c2.example" for i in rec1["iocs"])

    # New reporting arrives
    respx.get("https://research.example.org/atom").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_research.xml")))
    r = pipeline.run_ingest(conn, force=True, only=["fx-research"])
    res = watch.match_new_articles(conn, r["new_articles"])
    assert res == {wid: 1}
    rec2 = watch.latest_summary(conn, wid)
    assert rec2["version"] == 2
    assert rec2["changes"], "changes must be recorded"
    for item in rec2["confirmed"] + rec2["uncertain"]:
        assert item["article_ids"], "every claim must cite evidence"
    ev = conn.execute("SELECT we.significance, we.assessment FROM watch_evidence we JOIN articles a ON a.id=we.article_id "
                      "WHERE we.watch_id=? AND a.guid='res-2'", (wid,)).fetchone()
    assert ev is not None and ev["significance"] in ("important", "meaningful") and ev["assessment"]
    notes = conn.execute("SELECT * FROM notifications WHERE watch_id=?", (wid,)).fetchall()
    assert len(notes) == 1
    # duplicate notification suppressed: re-running matching creates nothing new
    watch.match_new_articles(conn, r["new_articles"])
    assert conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=?", (wid,)).fetchone()[0] == 1
    # history preserved
    assert conn.execute("SELECT COUNT(*) FROM watch_summaries WHERE watch_id=?", (wid,)).fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM watch_timeline WHERE watch_id=? AND event_type='evidence'", (wid,)).fetchone()[0] == 2


@respx.mock
def test_vulnerability_watch_and_silent(conn, fixture_sources):
    _ingest_split(conn)
    wid, _ = watch.create_watch(conn, kind="vulnerability", title="CVE-2099-0001 Exampleware VPN", notify_pref="silent")
    assert jloads(conn.execute("SELECT identifiers FROM watches WHERE id=?", (wid,)).fetchone()[0])[0] == "CVE-2099-0001"
    assert conn.execute("SELECT COUNT(*) FROM watch_evidence WHERE watch_id=? AND status='linked'", (wid,)).fetchone()[0] == 1
    respx.get("https://research.example.org/atom").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_research.xml")))
    r = pipeline.run_ingest(conn, force=True, only=["fx-research"])
    watch.match_new_articles(conn, r["new_articles"])
    assert conn.execute("SELECT COUNT(*) FROM watch_evidence WHERE watch_id=? AND status='linked'", (wid,)).fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=?", (wid,)).fetchone()[0] == 0
    rec = watch.latest_summary(conn, wid)
    assert any(t["id"] == "T1190" and not t["inferred"] for t in rec["techniques"])


def test_incident_watch_requires_identifier(conn):
    with pytest.raises(ValueError):
        watch.create_watch(conn, kind="incident", title="Some incident", identifiers=[], aliases=[])


@respx.mock
def test_heuristic_briefing_cites_sources(conn, fixture_sources):
    mock_feeds()
    r = pipeline.run_ingest(conn, force=True)
    bid = briefing.generate(conn, hours=24 * 365 * 5, notify_user=False)
    b = conn.execute("SELECT * FROM briefings WHERE id=?", (bid,)).fetchone()
    content = jloads(b["content_json"], {})
    assert b["method"] == "heuristic"
    assert content["items"]
    valid = set(r["new_articles"])
    for it in content["items"]:
        assert it["article_ids"] and set(it["article_ids"]) <= valid


# ------------------------------------------------------------------ AI (mocked)
class FakeMessages:
    def __init__(self, payload, stop="end_turn"):
        self.payload, self.stop, self.calls = payload, stop, 0

    def create(self, **kw):
        self.calls += 1
        assert "<untrusted_source" in kw["messages"][0]["content"]
        assert "untrusted third-party text" in kw["system"]
        return SimpleNamespace(stop_reason=self.stop, model="claude-opus-5-5",
                               usage=SimpleNamespace(input_tokens=1000, output_tokens=200, cache_creation_input_tokens=0, cache_read_input_tokens=0),
                               content=[SimpleNamespace(type="text", text=json.dumps(self.payload))])


@pytest.fixture
def fake_ai(monkeypatch):
    from app import config

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    config.get_settings.cache_clear()
    holder = {}

    def install(payload, stop="end_turn"):
        msgs = FakeMessages(payload, stop)
        client = SimpleNamespace(messages=msgs, beta=SimpleNamespace(messages=msgs))
        monkeypatch.setattr(ai, "_client", lambda: client)
        holder["m"] = msgs
        return msgs
    return install


def test_ai_summary_cached_and_grounded(conn, fake_ai, fixture_sources):
    payload = {"summary": "S", "why_it_matters": "W", "technical": "", "exploitation_status": "confirmed",
               "entities": [{"type": "victim_org", "value": "Contoso Health"}, {"type": "actor", "value": "Imaginary Panda"}]}
    msgs = fake_ai(payload)
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    aid = conn.execute("INSERT INTO articles(source_id,url,canonical_url,title,summary_text,retrieved_at,published_at) VALUES(?,?,?,?,?,?,?)",
                       (src, "https://x.example/a", "https://x.example/a", "Contoso Health attack", "Contoso Health was attacked.", "2026-11-09T00:00:00Z", "2026-11-09T00:00:00Z")).lastrowid
    art = dict(conn.execute("SELECT a.*, 'FX' AS source_name FROM articles a WHERE id=?", (aid,)).fetchone())
    out = ai.summarise_article(conn, art)
    ai.summarise_article(conn, art)
    assert msgs.calls == 1  # second call served from cache
    pipeline.apply_ai_entities(conn, art, out)
    vals = {r[0] for r in conn.execute("SELECT e.value FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?", (aid,))}
    assert "Contoso Health" in vals and "Imaginary Panda" not in vals  # ungrounded entity rejected
    st = ai.budget_status(conn)
    assert st["requests"] == 1 and st["spent_usd"] > 0


def test_ai_budget_enforced(conn, fake_ai, monkeypatch):
    monkeypatch.setenv("TW_AI_DAILY_BUDGET_USD", "0.0001")
    from app import config
    config.get_settings.cache_clear()
    fake_ai({"summary": "S", "why_it_matters": "W", "technical": "", "exploitation_status": "confirmed", "entities": []})
    ai.reset_run_counter()
    ai.summarise_article(conn, {"id": 1, "title": "a", "summary_text": "b", "content_text": ""})
    with pytest.raises(ai.AIUnavailable):
        ai.summarise_article(conn, {"id": 2, "title": "c", "summary_text": "d", "content_text": ""})


def test_ai_refusal_handled(conn, fake_ai):
    fake_ai({}, stop="refusal")
    ai.reset_run_counter()
    with pytest.raises(ai.AIUnavailable):
        ai.summarise_article(conn, {"id": 1, "title": "a", "summary_text": "b", "content_text": ""})


@respx.mock
def test_ai_watch_update_drops_uncited_claims(conn, fake_ai, fixture_sources):
    _ingest_split(conn)
    origin = conn.execute("SELECT id FROM articles WHERE guid='news-2'").fetchone()[0]
    fake_ai({"summary": "Contoso Health was hit [E%d]. Fake claim [E9999]." % origin,
             "confirmed": [{"claim": "Contoso Health attacked", "evidence_ids": [f"E{origin}"]}, {"claim": "Invented", "evidence_ids": ["E9999"]}],
             "uncertain": [], "changes": [], "detection": [], "techniques": [{"id": "T1486", "evidence_ids": [f"E{origin}"]}],
             "new_evidence_assessment": [{"evidence_id": f"E{origin}", "significance": "important", "reason": "initial"}]})
    wid, _ = watch.create_watch(conn, kind="incident", title="Contoso Health ransomware attack", identifiers=["Contoso Health"], origin_article_id=origin)
    rec = watch.latest_summary(conn, wid)
    assert rec["method"] == "ai"
    assert [c["claim"] for c in rec["confirmed"]] == ["Contoso Health attacked"]
    assert "[E9999]" not in rec["summary"]


# ------------------------------------------------------------------------ API
@pytest.fixture
def client(conn):
    from app.auth import hash_password
    from app.main import create_app

    conn.execute("INSERT INTO users(username, password_hash) VALUES('analyst', ?)", (hash_password("correct horse battery staple"),))
    return TestClient(create_app())


H = {"X-TW-Request": "1"}


def login(client):
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "correct horse battery staple"})
    assert r.status_code == 200
    return r


def test_api_requires_auth(client):
    for path in ["/api/today", "/api/articles", "/api/breaking", "/api/vulnerabilities", "/api/watches", "/api/bookmarks",
                 "/api/notifications", "/api/search?q=test", "/api/sources", "/api/status", "/api/history", "/api/auth/me"]:
        assert client.get(path).status_code == 401, path
    assert client.post("/api/watches", json={"kind": "topic", "title": "x"}, headers=H).status_code == 401
    assert client.get("/api/health").status_code == 200


def test_login_rate_limit_and_cookie(client):
    for _ in range(8):
        assert client.post("/api/auth/login", json={"username": "analyst", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "analyst", "password": "correct horse battery staple"}).status_code == 429


def test_session_cookie_flags(client):
    r = login(client)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_csrf_header_required(client):
    login(client)
    assert client.post("/api/visit").status_code == 403
    assert client.post("/api/visit", headers=H).status_code == 200


@respx.mock
def test_api_flows(client, conn, fixture_sources):
    mock_feeds()
    pipeline.run_ingest(conn, force=True)
    login(client)
    today = client.get("/api/today").json()
    assert today["since_last_visit"]["count"] >= 1
    arts = client.get("/api/articles").json()["items"]
    assert arts
    aid = next(a["id"] for a in arts if "Contoso" in a["title"])
    d = client.get(f"/api/articles/{aid}").json()
    assert d["url"].startswith("https://news.example.com/")
    assert d["watch_suggestions"]
    assert client.put(f"/api/bookmarks/{aid}", json={"note": "check", "tags": ["ransomware"]}, headers=H).status_code == 200
    assert client.get("/api/bookmarks").json()[0]["bookmark"]["note"] == "check"
    assert client.post(f"/api/articles/{aid}/read", headers=H).status_code == 200
    assert client.get("/api/history").json()[0]["id"] == aid
    r = client.post("/api/watches", json={"kind": "incident", "title": "Contoso Health attack", "identifiers": ["Contoso Health"],
                                          "origin_article_id": aid}, headers=H)
    assert r.status_code == 201
    wid = r.json()["id"]
    w = client.get(f"/api/watches/{wid}").json()
    assert w["record"]["version"] >= 1 and w["evidence"] and w["timeline"]
    assert client.patch(f"/api/watches/{wid}", json={"notify_pref": "digest", "notes": "my notes"}, headers=H).status_code == 200
    assert client.get("/api/search?q=Contoso").json()["articles"]
    assert client.get("/api/vulnerabilities?kev=true").json()["items"]
    assert client.get("/api/vulnerabilities/CVE-2099-0002").json()["kev"] is True
    r = client.post(f"/api/articles/{aid}/summarise", headers=H)
    assert r.status_code == 503  # no AI key: graceful
    assert client.get("/api/search?q=%22%29%20OR%20*").status_code == 200  # FTS injection-safe
    assert client.post("/api/auth/logout", headers=H).status_code == 200
    assert client.get("/api/today").status_code == 401


def test_security_headers(client):
    r = client.get("/api/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_cve_mentioned_only_in_body_links_to_vulnerability_watch(conn, fixture_sources):
    """Regression: an explicit CVE ID in the body (e.g. a CISA 'adds N KEVs' post) is a definitive match."""
    src = conn.execute("SELECT id FROM sources WHERE key='fx-news'").fetchone()[0]
    aid = conn.execute(
        "INSERT INTO articles(source_id,url,canonical_url,title,summary_text,retrieved_at,published_at) VALUES(?,?,?,?,?,?,?)",
        (src, "https://news.example.com/kev-adds", "https://news.example.com/kev-adds", "CISA Adds Six Known Exploited Vulnerabilities to Catalog",
         "CISA added CVE-2099-0007 Example Gateway Command Injection and five others.", "2026-11-09T00:00:00Z", "2026-11-09T00:00:00Z")).lastrowid
    pipeline.process_article(conn, aid)
    wid, _ = watch.create_watch(conn, kind="vulnerability", title="CVE-2099-0007 Example Gateway")
    st = conn.execute("SELECT status FROM watch_evidence WHERE watch_id=? AND article_id=?", (wid, aid)).fetchone()
    assert st and st[0] == "linked"
