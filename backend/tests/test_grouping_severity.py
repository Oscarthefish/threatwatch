"""Same-story grouping across outlets, and severity for roundups, passing CVE mentions and court follow-ups.

Headlines are SYNTHETIC (fictional products and companies) but shaped like real coverage of one story.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.db import get_setting
from app.ingest import pipeline, sources
from app.intel import classify, dedupe

T0 = datetime(2026, 11, 17, 9, tzinfo=timezone.utc)


@pytest.fixture
def srcs(conn):
    pipeline.sync_sources(conn)
    keys = ["bleepingcomputer", "the-record", "risky-bulletin", "huntress", "sans-isc"]
    return {k: pipeline._source_dict(conn.execute("SELECT * FROM sources WHERE key=?", (k,)).fetchone()) for k in keys}


def add(conn, src, title, hours=0, summary="SYNTHETIC summary."):
    aid = pipeline.store_item(conn, src, sources.RawItem(
        url=f"https://example.com/{abs(hash((src['key'], title)))}", title=title, summary_text=summary,
        published_at=T0 + timedelta(hours=hours)))
    pipeline.process_article(conn, aid)
    return aid


def cluster(conn, aid):
    return conn.execute("SELECT cluster_id FROM articles WHERE id=?", (aid,)).fetchone()[0]


def test_differently_worded_coverage_of_one_story_is_grouped(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "Quillstack supply chain attack infects major brands' sites with malware")
    b = add(conn, srcs["the-record"], "Website platform Quillstack confirms hackers put malicious code into customer sites", 3)
    c = add(conn, srcs["risky-bulletin"], "Risky Bulletin: Hackers hijack Quillstack to deliver malware on 178 popular sites", 20)
    assert cluster(conn, a) == cluster(conn, b) == cluster(conn, c) == a


def test_common_names_and_ordinary_words_do_not_group(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "Baker Ridge notifies clients of data breach at third-party provider")
    b = add(conn, srcs["the-record"], "Tidewater confirms employee data breach tied to cloud service provider", 2)
    c = add(conn, srcs["bleepingcomputer"], "Romania says it stopped Russian cyberattack targeting government emails", 4)
    d = add(conn, srcs["the-record"], "NATO withdraws Russian taxi app travel advice for defence conference", 5)
    assert len({cluster(conn, x) for x in (a, b, c, d)}) == 4


def test_loose_matches_do_not_chain_through_a_story(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "California sues Lumenai over AI agents escaping sandboxes")
    b = add(conn, srcs["the-record"], "California sues Lumenai for Hugging Face and other incidents", 2)
    c = add(conn, srcs["huntress"], "Researchers hijack Hugging Face account for popular Kokoro AI model", 6)
    assert cluster(conn, b) == cluster(conn, a) and cluster(conn, c) == c  # matched only against the story's first report


def test_shared_name_outside_48_hours_is_a_separate_story(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "Hackers now exploit Quillstack ESG flaws to gain root access")
    b = add(conn, srcs["the-record"], "Quillstack links cloud breach to automated cyberattack", 60)
    assert cluster(conn, a) != cluster(conn, b)


def test_headline_names():
    assert dedupe.headline_names("Uber notifies drivers of data breach") == set()
    assert dedupe.headline_names("Hackers hijack Quillstack to deliver malware") == {"quillstack"}
    assert dedupe.headline_names("SCKit Worm Installs Rogue ScreenConnect Clients Across Endpoints") is None  # Title Case


def test_rules_change_regroups_stored_articles_once(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "Quillstack supply chain attack infects major brands' sites with malware")
    b = add(conn, srcs["the-record"], "Website platform Quillstack confirms hackers put malicious code into customer sites", 3)
    conn.execute("UPDATE articles SET cluster_id=id")  # as stored by the old rules
    assert pipeline.reprocess_if_rules_changed(conn) == 2
    assert cluster(conn, b) == a and get_setting(conn, "cluster_rules_version") == pipeline.CLUSTER_RULES_VERSION
    assert pipeline.reprocess_if_rules_changed(conn) == 0


def test_rescoring_keeps_story_grouping(conn, srcs):
    a = add(conn, srcs["bleepingcomputer"], "Quillstack supply chain attack infects major brands' sites with malware")
    b = add(conn, srcs["the-record"], "Website platform Quillstack confirms hackers put malicious code into customer sites", 3)
    pipeline.process_article(conn, a)  # e.g. a mentioned CVE was just added to KEV
    assert cluster(conn, a) == cluster(conn, b) == a


# ------------------------------------------------------------------ severity
SRC = {"name": "Example News", "kind": "rss", "authority": 2, "region": "GLOBAL", "default_sections": []}
KEV = {"cve_id": "CVE-2099-1111", "kev": 1, "cvss_score": 9.8, "epss": 0.9, "product": "Gatekeeper VPN"}


def test_passing_kev_mention_is_not_critical():
    body = "SYNTHETIC guest diary about workflow. " + "Filler. " * 200 + "Our honeypot saw CVE-2099-1111 probes."
    c = classify.classify("Treat your honeypot analysis like code", body, SRC, {"cve": {"cve-2099-1111"}}, [KEV],
                          lead="A guest diary on analysis workflow.")
    assert c.severity <= 2 and "breaking" not in c.sections
    assert any("not the article's main subject" in r for r in c.reasons)


def test_kev_cve_in_headline_summary_or_product_is_the_subject():
    for title, lead in [("Gatekeeper VPN flaw CVE-2099-1111 exploited", ""),
                        ("Patch now: attackers hit edge devices", "CVE-2099-1111 is being exploited."),
                        ("Crew abuses Gatekeeper VPN to reach networks", "Intrusions traced to an edge appliance.")]:
        c = classify.classify(title, f"{lead}\n" + "Detail. " * 300 + "CVE-2099-1111", SRC, {"cve": {"cve-2099-1111"}}, [KEV], lead=lead)
        assert c.severity == 4 and "breaking" in c.sections, title


def test_roundups_are_never_critical_or_breaking():
    c = classify.classify("Risky Bulletin: Zero-day CVE-2099-1111 exploited in the wild", "CVE-2099-1111 zero-day exploited",
                          SRC, {"cve": {"cve-2099-1111"}}, [KEV], lead="CVE-2099-1111 zero-day exploited")
    assert c.severity == 2 and "breaking" not in c.sections and "roundup" in c.tags


def test_court_follow_up_is_not_a_live_incident():
    court = classify.classify("Court clears brothers of $25 million crypto heist charges", "", SRC, {}, [], lead="")
    breach = classify.classify("Railway breach leads to $740,000 in fraudulent AI charges", "", SRC, {}, [], lead="")
    assert court.severity <= 1 and "breaking" not in court.sections
    assert breach.severity >= 2 and any("incident" in r for r in breach.reasons)
