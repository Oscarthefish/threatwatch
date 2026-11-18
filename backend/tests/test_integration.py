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


@respx.mock
def test_roundup_mention_is_minor_and_silent(conn, fixture_sources):
    """A newsletter roundup that mentions a followed CVE in passing links, but never counts as important or notifies."""
    _ingest_split(conn)
    wid, _ = watch.create_watch(conn, kind="vulnerability", title="CVE-2099-0001", notify_pref="all")
    src = conn.execute("SELECT id FROM sources WHERE key='fx-research'").fetchone()[0]
    aid = conn.execute(
        "INSERT INTO articles(source_id,url,canonical_url,title,summary_text,retrieved_at,published_at) VALUES(?,?,?,?,?,?,?)",
        (src, "https://research.example.org/weekly", "https://research.example.org/weekly", "Week in review: Akira, LockBit and more",
         "Roundup. Exploited CVE-2099-0001 also patched. Elsewhere LockBit and Akira hit Fabrikam.", "2026-11-09T07:00:00Z", "2026-11-09T07:00:00Z")).lastrowid
    pipeline.process_article(conn, aid)
    watch.match_new_articles(conn, [aid])
    ev = conn.execute("SELECT status, significance FROM watch_evidence WHERE watch_id=? AND article_id=?", (wid, aid)).fetchone()
    assert ev["status"] == "linked" and ev["significance"] == "minor"
    assert conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=? AND article_id=?", (wid, aid)).fetchone()[0] == 0


def test_feeds_hide_kev_announcements_but_search_finds_them(client, conn):
    from app.db import now_iso
    from app.ingest import pipeline

    pipeline.sync_sources(conn)
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    for i, title in enumerate(["CISA Adds Two Known Exploited Vulnerabilities to Catalog", "Example vendor patches exploited flaw"]):
        conn.execute(
            """INSERT INTO articles(source_id, url, canonical_url, title, title_tokens, summary_text, published_at, retrieved_at,
                                    sections, severity, confidence, score)
               VALUES(?,?,?,?,?,?,?,?,'["vulnerabilities"]',3,'official',50)""",
            (src, f"https://example.com/kev-{i}", f"https://example.com/kev-{i}", title, title.lower(), "examplekevword", now_iso(), now_iso()))
    conn.commit()
    login(client)
    feed = [a["title"] for a in client.get("/api/articles?section=vulnerabilities").json()["items"]]
    assert "Example vendor patches exploited flaw" in feed
    assert not any("Known Exploited" in t for t in feed)
    latest = [a["title"] for a in client.get("/api/articles").json()["items"]]
    assert not any("Known Exploited" in t for t in latest)
    found = [a["title"] for a in client.get("/api/articles?q=examplekevword").json()["items"]]
    assert any("Known Exploited" in t for t in found)


def test_trends_counts_stories_and_flags_backlog(client, conn):
    from datetime import timedelta

    from app.db import iso, utcnow
    from app.ingest import pipeline

    pipeline.sync_sources(conn)
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    now = utcnow()
    rows = [("Example ransomware hits retailer", 4, 1, '["ransomware"]'), ("Same story, second outlet", 4, 1, '["ransomware"]'),
            ("Example weekly roundup", 1, 2, '["roundup"]'), ("Older backlog item", 3, 40, '["phishing"]')]
    for i, (title, sev, age, tags) in enumerate(rows):
        conn.execute(
            """INSERT INTO articles(source_id, url, canonical_url, title, published_at, retrieved_at, sections, tags, severity, confidence, score)
               VALUES(?,?,?,?,?,?,'[]',?,?,'single-source',1)""",
            (src, f"https://example.com/t{i}", f"https://example.com/t{i}", title, iso(now - timedelta(days=age)), iso(now), tags, sev))
    ids = [r[0] for r in conn.execute("SELECT id FROM articles ORDER BY id")]
    conn.execute("UPDATE articles SET cluster_id=? WHERE id IN (?,?)", (ids[0], ids[0], ids[1]))  # two outlets, one story
    conn.commit()
    login(client)
    t = client.get("/api/trends?days=30").json()
    assert t["totals"]["current"]["reports"] == 2           # the two-outlet story counts once
    assert t["totals"]["current"]["critical_high"] == 1
    assert t["totals"]["previous"]["reports"] == 1
    assert t["comparison_indicative"] is True                # earlier period predates collection
    assert any(v["partial"] for v in t["volume"]) is True
    assert {x["name"] for x in t["topics"]} >= {"Ransomware"}


def test_group_profile_resolves_aliases_and_skips_roundups(client, conn):
    from datetime import timedelta

    from app.db import iso, utcnow
    from app.ingest import pipeline

    pipeline.sync_sources(conn)
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    now = utcnow()
    conn.execute("INSERT INTO entities(type, value, normalized) VALUES('actor', 'Turla', 'turla')")
    ent = conn.execute("SELECT id FROM entities WHERE type='actor' AND value='Turla'").fetchone()[0]
    for i, (title, tags, sev) in enumerate([("Example: Turla targets embassies", '[]', 3), ("Example weekly roundup", '["roundup"]', 1)]):
        conn.execute(
            """INSERT INTO articles(source_id, url, canonical_url, title, published_at, retrieved_at, sections, tags, severity, confidence, score)
               VALUES(?,?,?,?,?,?,'[]',?,?,'single-source',1)""",
            (src, f"https://example.com/g{i}", f"https://example.com/g{i}", title, iso(now - timedelta(days=2)), iso(now), tags, sev))
        aid = conn.execute("SELECT id FROM articles WHERE url=?", (f"https://example.com/g{i}",)).fetchone()[0]
        conn.execute("INSERT INTO article_entities(article_id, entity_id, method) VALUES(?,?,'dictionary')", (aid, ent))
    conn.commit()
    login(client)
    g = client.get("/api/groups/actor/Secret%20Blizzard").json()   # an alias resolves to the canonical group
    assert g["name"] == "Turla" and "Secret Blizzard" in g["aliases"]
    assert g["stories"] == 1 and g["roundups"] == 1               # the roundup is listed, not counted
    assert sum(w["high"] for w in g["weekly"]) == 1
    assert client.get("/api/groups/actor/Not%20A%20Real%20Group").status_code == 404
    assert client.get("/api/groups/vendor/Example").status_code == 404


def test_ai_tiers_pick_models_prices_and_fallback(conn, fake_ai, fixture_sources):
    msgs = fake_ai({"summary": "S", "why_it_matters": "W", "technical": "", "exploitation_status": "none_reported", "entities": []})
    seen = []
    orig = msgs.create
    msgs.create = lambda **kw: (seen.append(kw), orig(**kw))[1]
    src = conn.execute("SELECT id FROM sources LIMIT 1").fetchone()[0]
    aid = conn.execute("INSERT INTO articles(source_id,url,canonical_url,title,summary_text,retrieved_at,published_at) VALUES(?,?,?,?,?,?,?)",
                       (src, "https://x.example/t", "https://x.example/t", "Example story", "Example text.", "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z")).lastrowid
    ai.summarise_article(conn, dict(conn.execute("SELECT a.*, 'FX' AS source_name FROM articles a WHERE id=?", (aid,)).fetchone()))
    assert seen[-1]["model"] == "claude-haiku-5-5" and "betas" not in seen[-1]   # fast tier; Haiku has no server-side fallback
    spent = conn.execute("SELECT cost_usd FROM ai_usage").fetchone()[0]
    assert abs(spent - (1000 / 1e6 * 0.10 + 200 / 1e6 * 0.50)) < 1e-9                # priced as Haiku, not Opus
    ai.structured(conn, kind="briefing", system="sys", user="<untrusted_source>x</untrusted_source>", schema={"type": "object"})
    assert seen[-1]["model"] == "claude-sonnet-5-5" and seen[-1].get("betas")         # deep tier keeps the fallback
    assert ai.budget_status(conn)["budget_usd"] == 0.50


def _login_as(client, remember: bool, ua: str):
    r = client.post("/api/auth/login", headers={"user-agent": ua},
                    json={"username": "analyst", "password": "correct horse battery staple", "remember": remember})
    assert r.status_code == 200 and r.json()["trusted"] is remember
    return r


PHONE = "Mozilla/5.0 (Linux; Android 16; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36"
MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"


def test_trusted_device_session_renews_and_normal_session_does_not(client, conn):
    from datetime import timedelta

    from app.db import iso, utcnow
    r = _login_as(client, True, PHONE)
    assert "max-age=15552000" in r.headers["set-cookie"].lower()  # 180 days
    row = conn.execute("SELECT rowid, trusted, expires_at FROM sessions").fetchone()
    assert row["trusted"] == 1
    # two months later the device opens the app: expiry moves forward and the cookie is re-issued
    conn.execute("UPDATE sessions SET expires_at=? WHERE rowid=?", (iso(utcnow() + timedelta(days=120)), row["rowid"]))
    me = client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["trusted"] is True
    assert "max-age=15552000" in me.headers.get("set-cookie", "").lower()
    renewed = conn.execute("SELECT expires_at FROM sessions WHERE rowid=?", (row["rowid"],)).fetchone()[0]
    assert renewed > iso(utcnow() + timedelta(days=179))
    # used again the same day: no rewrite
    assert "set-cookie" not in client.get("/api/auth/me").headers

    client.cookies.clear()
    r = _login_as(client, False, MAC)
    assert "max-age=2592000" in r.headers["set-cookie"].lower()  # 30 days, fixed
    conn.execute("UPDATE sessions SET expires_at=? WHERE trusted=0", (iso(utcnow() + timedelta(days=5)),))
    assert "set-cookie" not in client.get("/api/auth/me").headers
    assert conn.execute("SELECT expires_at FROM sessions WHERE trusted=0").fetchone()[0] < iso(utcnow() + timedelta(days=6))
    # an expired trusted session is not revived
    conn.execute("UPDATE sessions SET expires_at=? WHERE trusted=0", (iso(utcnow() - timedelta(minutes=1)),))
    assert client.get("/api/auth/me").status_code == 401


def test_signed_in_devices_listed_and_one_can_be_signed_out(client, conn):
    from fastapi.testclient import TestClient
    phone = TestClient(client.app)
    _login_as(phone, True, PHONE)
    _login_as(client, False, MAC)
    data = client.get("/api/auth/sessions").json()
    devs = {d["device"]: d for d in data["sessions"]}
    assert set(devs) == {"Chrome on Android", "Chrome on Mac"}
    assert devs["Chrome on Mac"]["current"] and not devs["Chrome on Android"]["current"]
    assert devs["Chrome on Android"]["trusted"] and data["trusted_days"] == 180
    assert "token_hash" not in devs["Chrome on Mac"] and "user_agent" not in devs["Chrome on Mac"]
    pid = devs["Chrome on Android"]["id"]
    assert client.delete(f"/api/auth/sessions/{pid}").status_code == 403  # CSRF header required
    assert client.delete(f"/api/auth/sessions/{pid}", headers=H).status_code == 200
    assert phone.get("/api/auth/me").status_code == 401  # the lost phone is signed out
    assert client.get("/api/auth/me").status_code == 200
    assert client.delete(f"/api/auth/sessions/{pid}", headers=H).status_code == 404


def test_device_labels():
    from app.auth import device_label
    assert device_label(PHONE) == "Chrome on Android"
    assert device_label("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1") == "Safari on iPhone"
    assert device_label("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 Edg/141.0") == "Edge on Windows"
    assert device_label("") == "Unknown device"
