"""Vendor research and weekly statistics sources (Hudson Rock): catalogue, parsing, severity, follows, duplicates.

The catalogue entries are tested as shipped; ingestion uses copies pointed at synthetic ``.example`` feeds.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import httpx
import pytest
import respx

from app.db import jloads
from app.ingest import pipeline, sources
from app.intel import watch
from tests.conftest import fixture_bytes

RESEARCH_URL = "https://stealers.example/research/feed/"
WEEKLY_URL = "https://stealers.example/feed/?post_type=threat-report"


def _shipped(key: str) -> sources.SourceDef:
    return next(s for s in sources.DEFAULT_SOURCES if s.key == key)


def test_catalogue_entries():
    research, weekly = _shipped("hudson-rock"), _shipped("hudson-rock-weekly")
    for s in (research, weekly):
        assert s.kind == "rss" and s.url.startswith("https://www.infostealers.com/") and s.enabled
        assert s.sections == ["threat-intel"] and s.authority == 2
    # research feed, not the site-wide feed that also carries the compromised-domain statistics report
    assert research.url.endswith("/learn-info-stealers/feed/") and research.max_severity == 4
    assert weekly.max_severity == 1 and sources.SEVERITY_CAPS["hudson-rock-weekly"] == 1
    assert len({s.key for s in sources.DEFAULT_SOURCES}) == len(sources.DEFAULT_SOURCES)


@pytest.fixture
def vendor_sources(conn, monkeypatch):
    defs = [
        dataclasses.replace(_shipped("hudson-rock"), url=RESEARCH_URL),
        dataclasses.replace(_shipped("hudson-rock-weekly"), url=WEEKLY_URL),
        sources.SourceDef("fx-news", "FIXTURE News", "rss", "https://news.example.com/feed", "https://news.example.com/", 2, "GLOBAL", []),
    ]
    monkeypatch.setattr(sources, "DEFAULT_SOURCES", defs)
    monkeypatch.setattr(pipeline, "DEFAULT_SOURCES", defs)
    pipeline.sync_sources(conn)
    return defs


def _mock(research=None, weekly=None):
    respx.get(RESEARCH_URL).mock(return_value=research or httpx.Response(
        200, content=fixture_bytes("feed_wp_research.xml"), headers={"etag": 'W/"r1"'}))
    respx.get(WEEKLY_URL).mock(return_value=weekly or httpx.Response(200, content=fixture_bytes("feed_wp_weekly.xml")))


def _article(conn, url_part: str):
    return conn.execute("SELECT a.*, s.key AS source_key, s.name AS source_name FROM articles a JOIN sources s ON s.id=a.source_id "
                        "WHERE a.url LIKE ?", (f"%{url_part}%",)).fetchone()


@respx.mock
def test_research_feed_parsed_with_attribution_and_entities(conn, vendor_sources):
    _mock()
    r = pipeline.run_ingest(conn, force=True, only=["hudson-rock"])
    assert r["sources"]["hudson-rock"] == "2 new"
    a = _article(conn, "remus-stealer-mailbox-module")
    assert a["title"] == "Remus Stealer Adds a Mailbox Persistence Module: FIXTURE Lab Investigates"  # title kept as published
    assert a["url"] == "https://stealers.example/article/remus-stealer-mailbox-module/"
    assert a["published_at"].startswith("2026-11-09T13:33:14")
    assert a["source_name"] == "Hudson Rock research (InfoStealers)" and a["author"] == "FIXTURE Analyst"
    ents = {(r[0], r[1]) for r in conn.execute(
        "SELECT e.type, e.value FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?", (a["id"],))}
    assert ("malware", "Remus Stealer") in ents
    assert "threat-intel" in jloads(a["sections"]) and "breaking" not in jloads(a["sections"])
    assert a["severity"] <= 2
    # a vendor announcement in the same feed stays low and out of Breaking
    pr = _article(conn, "fixture-partnership")
    assert pr["severity"] <= 1 and "breaking" not in jloads(pr["sections"])
    # conditional requests are used next time
    assert conn.execute("SELECT etag FROM sources WHERE key='hudson-rock'").fetchone()[0] == 'W/"r1"'


def test_remus_alone_needs_a_qualifier():
    from app.intel import entities
    names = lambda t: {e.value for e in entities.extract(t, "")}  # noqa: E731
    assert "Remus Stealer" in names("Remus Stealer adds a mailbox module")
    assert "Remus Stealer" in names("The Remus infostealer adds a module")
    assert "Remus Stealer" not in names("Remus Lupin is a character in a novel")


@respx.mock
def test_weekly_statistics_report_is_context_not_an_alert(conn, vendor_sources):
    """Large counts and alarming words in a statistics report never raise severity, reach Breaking, or move a follow."""
    wid_click, _ = watch.create_watch(conn, kind="malware", title="ClickFix", notify_pref="all")
    wid_remus, _ = watch.create_watch(conn, kind="malware", title="Remus Stealer", notify_pref="all")
    _mock()
    r = pipeline.run_ingest(conn, force=True, only=["hudson-rock-weekly"])
    watch.match_new_articles(conn, r["new_articles"])
    a = _article(conn, "threat-feeds-weekly-report")
    tags, reasons = set(jloads(a["tags"])), jloads(a["severity_reasons"])
    assert a["title"] == "Threat Feeds Weekly Report: 2026-11-09 – 2026-11-16"
    assert "roundup" in tags
    assert a["severity"] <= 1 and "breaking" not in jloads(a["sections"])
    assert any("weekly report" in x for x in reasons)
    ev = lambda wid: conn.execute("SELECT status, significance FROM watch_evidence WHERE watch_id=? AND article_id=?",  # noqa: E731
                                  (wid, a["id"])).fetchone()
    # named in the counts table: linked as context only, never a development
    assert ev(wid_remus)["status"] == "linked" and ev(wid_remus)["significance"] == "minor"
    # "ClickFix Monitor" in passing: not even queued for review
    assert ev(wid_click) is None
    for wid in (wid_click, wid_remus):
        assert conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=?", (wid,)).fetchone()[0] == 0
    # lower-case family names in a counts table are not extracted as subjects
    vals = {r[0] for r in conn.execute(
        "SELECT e.value FROM article_entities ae JOIN entities e ON e.id=ae.entity_id WHERE ae.article_id=?", (a["id"],))}
    assert not vals & {"Lumma Stealer", "Vidar", "SocGholish", "Atomic Stealer"}


@respx.mock
def test_followed_family_gets_one_notification_across_publishers(conn, vendor_sources):
    wid, _ = watch.create_watch(conn, kind="malware", title="Remus Stealer", notify_pref="all")
    _mock()
    r = pipeline.run_ingest(conn, force=True, only=["hudson-rock"])
    watch.match_new_articles(conn, r["new_articles"])
    first = _article(conn, "remus-stealer-mailbox-module")
    assert conn.execute("SELECT status FROM watch_evidence WHERE watch_id=? AND article_id=?", (wid, first["id"])).fetchone()[0] == "linked"
    before = conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=?", (wid,)).fetchone()[0]
    assert before == 1

    # another publisher re-reports the same research a few hours later
    src = pipeline._source_dict(conn.execute("SELECT * FROM sources WHERE key='fx-news'").fetchone())
    dup = pipeline.store_item(conn, src, sources.RawItem(
        url="https://news.example.com/remus", title="Remus Stealer adds mailbox persistence module, researchers find",
        summary_text="FIXTURE Lab says the Remus Stealer developer advertises mailbox persistence.",
        published_at=datetime(2026, 11, 9, 18, tzinfo=timezone.utc)))
    pipeline.process_article(conn, dup)
    assert conn.execute("SELECT cluster_id FROM articles WHERE id=?", (dup,)).fetchone()[0] == first["cluster_id"]
    watch.match_new_articles(conn, [dup])
    assert conn.execute("SELECT COUNT(*) FROM notifications WHERE watch_id=?", (wid,)).fetchone()[0] == before


@respx.mock
def test_blocked_or_broken_vendor_feed_does_not_affect_other_sources(conn, vendor_sources):
    # e.g. a CDN challenge page instead of the feed, and an HTML page where RSS was expected
    _mock(research=httpx.Response(403, content=b"<html>challenge</html>", headers={"content-type": "text/html"}),
          weekly=httpx.Response(200, content=b"<html><body>Not a feed</body></html>", headers={"content-type": "text/html"}))
    respx.get("https://news.example.com/feed").mock(return_value=httpx.Response(200, content=fixture_bytes("feed_news.xml")))
    r = pipeline.run_ingest(conn, force=True)
    assert r["sources"]["hudson-rock"].startswith("error")
    assert r["sources"]["hudson-rock-weekly"] == "0 new"
    assert r["sources"]["fx-news"].endswith("new") and not r["sources"]["fx-news"].startswith("0")
    row = conn.execute("SELECT consecutive_failures, last_error FROM sources WHERE key='hudson-rock'").fetchone()
    assert row[0] == 1 and row[1]
