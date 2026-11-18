"""Source adapters and the default source catalogue.

To add a source: append a ``SourceDef`` to ``DEFAULT_SOURCES``. For a new
retrieval method, subclass ``Adapter`` and register it in ``ADAPTERS``.
Every adapter returns ``RawItem`` objects pointing at the original article URL.
"""
from __future__ import annotations

import calendar
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urljoin

import feedparser

from .fetcher import FetchResult, fetch
from .sanitize import clean_title, html_to_text

log = logging.getLogger(__name__)


@dataclass
class SourceDef:
    key: str
    name: str
    kind: str
    url: str
    homepage: str
    authority: int = 2
    region: str = "GLOBAL"
    sections: list[str] = field(default_factory=list)
    interval_minutes: int = 30
    enabled: bool = True
    max_severity: int = 4  # cap for release notes, podcasts and statistical reports that mention many subjects in passing


# Feed URLs were verified reachable on 2026-11-09.
DEFAULT_SOURCES: list[SourceDef] = [
    SourceDef("bleepingcomputer", "BleepingComputer", "rss", "https://www.bleepingcomputer.com/feed/",
              "https://www.bleepingcomputer.com/", 2, "GLOBAL", []),
    SourceDef("sans-isc", "SANS Internet Storm Center", "rss", "https://isc.sans.edu/rssfeed_full.xml",
              "https://isc.sans.edu/", 2, "GLOBAL", ["soc-dfir"]),
    SourceDef("dfir-report", "The DFIR Report", "rss", "https://thedfirreport.com/feed/",
              "https://thedfirreport.com/", 2, "GLOBAL", ["soc-dfir", "threat-intel"], 120),
    SourceDef("google-ti", "Google Threat Intelligence (Mandiant)", "rss",
              "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
              "https://cloud.google.com/blog/topics/threat-intelligence", 2, "GLOBAL", ["threat-intel"], 60),
    SourceDef("the-record", "The Record", "rss", "https://therecord.media/feed", "https://therecord.media/", 2, "GLOBAL", []),
    SourceDef("ncsc-nz", "NCSC New Zealand alerts", "ncsc_nz_html", "https://www.ncsc.govt.nz/alerts/",
              "https://www.ncsc.govt.nz/", 3, "NZ", ["nz-apac"], 60),
    SourceDef("cisa-kev", "CISA Known Exploited Vulnerabilities", "kev",
              "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
              "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", 3, "GLOBAL", ["vulnerabilities"], 60),
    SourceDef("first-epss", "FIRST EPSS", "epss", "https://api.first.org/data/v1/epss",
              "https://www.first.org/epss/", 3, "GLOBAL", ["vulnerabilities"], 720),
    SourceDef("mitre-attack", "MITRE ATT&CK groups and software", "attack",
              "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
              "https://attack.mitre.org/", 3, "GLOBAL", [], 10080),
    SourceDef("cve-org", "CVE.org record enrichment (CVSS, affected products)", "cve_enrich",
              "https://cveawg.mitre.org/api/cve/", "https://www.cve.org/", 3, "GLOBAL", ["vulnerabilities"], 60),
    SourceDef("risky-bulletin", "Risky Bulletin (Risky Business News)", "rss", "https://news.risky.biz/rss/",
              "https://news.risky.biz/", 2, "GLOBAL", [], 60),
    SourceDef("risky-business", "Risky Business podcast", "rss", "https://risky.biz/feeds/risky-business/",
              "https://risky.biz/", 2, "GLOBAL", [], 180, max_severity=2),
    SourceDef("cisa-advisories", "CISA Cybersecurity Advisories", "rss", "https://www.cisa.gov/cybersecurity-advisories/all.xml",
              "https://www.cisa.gov/news-events/cybersecurity-advisories", 3, "GLOBAL", ["vulnerabilities"], 60),
    SourceDef("asd-acsc-alerts", "ASD's ACSC alerts (Australia)", "rss", "https://www.cyber.gov.au/rss/alerts",
              "https://www.cyber.gov.au/", 3, "AU", ["nz-apac"], 60),
    SourceDef("microsoft-security", "Microsoft Security Blog", "rss", "https://www.microsoft.com/en-us/security/blog/feed/",
              "https://www.microsoft.com/en-us/security/blog/", 2, "GLOBAL", ["threat-intel"], 120),
    SourceDef("unit42", "Palo Alto Networks Unit 42", "rss", "https://unit42.paloaltonetworks.com/feed/",
              "https://unit42.paloaltonetworks.com/", 2, "GLOBAL", ["threat-intel"], 120),
    SourceDef("red-canary", "Red Canary Blog", "rss", "https://redcanary.com/blog/feed/", "https://redcanary.com/blog/",
              2, "GLOBAL", ["soc-dfir"], 180),
    SourceDef("huntress", "Huntress Blog", "rss", "https://www.huntress.com/blog/rss.xml", "https://www.huntress.com/blog",
              2, "GLOBAL", ["soc-dfir"], 180),
    SourceDef("sigma-releases", "SigmaHQ rule releases", "rss", "https://github.com/SigmaHQ/sigma/releases.atom",
              "https://github.com/SigmaHQ/sigma", 2, "GLOBAL", ["soc-dfir"], 720, max_severity=1),
    SourceDef("splunk-security-content", "Splunk Security Content releases", "rss",
              "https://github.com/splunk/security_content/releases.atom", "https://research.splunk.com/", 2, "GLOBAL",
              ["soc-dfir"], 720, max_severity=1),
    # Hudson Rock (verified 2026-11-17; robots.txt allows all). The research feed carries first-party
    # infostealer and ClickFix investigations about weekly; the site-wide /feed/ is avoided because it also
    # carries the compromised-domain statistics report. The Threat Feeds weekly report is aggregate sensor
    # counts (C2, phishing kit and ClickFix sightings), not confirmed infections or attacks, so it is capped at
    # low, treated as a roundup ("weekly report" in the title) and never moves a followed item.
    SourceDef("hudson-rock", "Hudson Rock research (InfoStealers)", "rss", "https://www.infostealers.com/learn-info-stealers/feed/",
              "https://www.infostealers.com/", 2, "GLOBAL", ["threat-intel"], 360),
    SourceDef("hudson-rock-weekly", "Hudson Rock Threat Feeds weekly report", "rss",
              "https://www.infostealers.com/feed/?post_type=threat-report", "https://www.infostealers.com/threat-report/",
              2, "GLOBAL", ["threat-intel"], 1440, max_severity=1),
]


@dataclass
class RawItem:
    url: str
    title: str
    summary_text: str = ""
    content_text: str = ""
    published_at: datetime | None = None
    author: str | None = None
    guid: str | None = None


@dataclass
class AdapterResult:
    items: list[RawItem] = field(default_factory=list)
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False
    detail: str = ""


class Adapter:
    """Base adapter. ``run`` fetches and parses; it must not touch the DB."""

    produces_articles = True

    def run(self, source: dict) -> AdapterResult:  # pragma: no cover - interface
        raise NotImplementedError


def _struct_to_dt(st) -> datetime | None:
    if not st:
        return None
    try:
        return datetime.fromtimestamp(calendar.timegm(st), tz=timezone.utc)
    except (OverflowError, ValueError, TypeError):
        return None


def parse_feed(content: bytes, base_url: str) -> list[RawItem]:
    parsed = feedparser.parse(content)
    items: list[RawItem] = []
    for e in parsed.entries[:200]:
        link = e.get("link") or ""
        if not link and e.get("links"):
            link = e["links"][0].get("href", "")
        if not link:
            continue
        link = urljoin(base_url, link.strip())
        if not link.startswith(("http://", "https://")):
            continue
        title = clean_title(e.get("title"))
        if not title:
            continue
        summary_html = e.get("summary") or e.get("description") or ""
        content_html = ""
        if e.get("content"):
            content_html = " ".join(c.get("value", "") for c in e["content"] if c.get("value"))
        summary = html_to_text(summary_html, max_len=2000)
        content = html_to_text(content_html, max_len=20000) if content_html else ""
        if content and summary and content.startswith(summary[:100]):
            summary = summary[:600]
        if not summary and content:
            summary = content[:600]
        published = _struct_to_dt(e.get("published_parsed") or e.get("updated_parsed"))
        items.append(
            RawItem(
                url=link,
                title=title,
                summary_text=summary,
                content_text=content,
                published_at=published,
                author=clean_title(e.get("author")) or None,
                guid=(e.get("id") or None),
            )
        )
    return items


class RSSAdapter(Adapter):
    def run(self, source: dict) -> AdapterResult:
        r: FetchResult = fetch(source["url"], etag=source.get("etag"), last_modified=source.get("last_modified"))
        if r.not_modified:
            return AdapterResult(not_modified=True, etag=source.get("etag"), last_modified=source.get("last_modified"))
        items = parse_feed(r.content, r.url)
        if "github.com" in source["url"] and source["url"].endswith("releases.atom"):
            for it in items:  # bare version tags ("v6.10.0") are meaningless out of context
                it.title = f"{source['name']}: {it.title}"
        return AdapterResult(items=items, etag=r.headers.get("etag"), last_modified=r.headers.get("last-modified"))


_NCSC_CARD = re.compile(
    r'<a\s+href="(?P<href>/alerts/[a-z0-9\-]+/)"[^>]*class="card__link"[^>]*>.*?'
    r'<h3 class="card__title">(?P<title>.*?)</h3>.*?'
    r'<p class="card__date">(?P<date>[^<]+)</p>',
    re.S,
)
_NCSC_DESC = re.compile(r'<meta name="description" content="([^"]*)"')
_NCSC_PUB = re.compile(r'"datePublished":"([^"]+)"')


class NcscNzAdapter(Adapter):
    """NCSC NZ publishes no RSS feed; parse the public alerts listing.

    Polite: one listing request per run (default hourly) plus one request per
    *new* alert to read its meta description and publication timestamp.
    """

    def __init__(self, known_urls: Iterable[str] | None = None, max_detail: int = 12):
        self.known = set(known_urls or [])
        self.max_detail = max_detail

    def run(self, source: dict) -> AdapterResult:
        r = fetch(source["url"], accept="text/html")
        page = r.text()
        items: list[RawItem] = []
        details = 0
        for m in _NCSC_CARD.finditer(page):
            url = urljoin(r.url, m.group("href"))
            title = clean_title(m.group("title"))
            pub = None
            try:
                pub = datetime.strptime(m.group("date").strip(), "%d %B %Y").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
            summary = ""
            if url not in self.known and details < self.max_detail:
                details += 1
                try:
                    d = fetch(url, accept="text/html").text()
                    md = _NCSC_DESC.search(d)
                    if md:
                        summary = html_to_text(md.group(1), max_len=1000)
                    mp = _NCSC_PUB.search(d)
                    if mp:
                        try:
                            pub = datetime.fromisoformat(mp.group(1)).astimezone(timezone.utc)
                        except ValueError:
                            pass
                except Exception as e:  # detail failure shouldn't drop the item
                    log.warning("ncsc detail fetch failed for %s: %s", url, e)
            items.append(RawItem(url=url, title=title, summary_text=summary, published_at=pub))
        return AdapterResult(items=items, detail=f"{len(items)} cards, {details} detail fetches")


ADAPTERS: dict[str, type[Adapter]] = {
    "rss": RSSAdapter,
    "ncsc_nz_html": NcscNzAdapter,
}


def parse_kev(content: bytes) -> tuple[str | None, list[dict]]:
    data = json.loads(content)
    return data.get("catalogVersion"), list(data.get("vulnerabilities", []))


SEVERITY_CAPS: dict[str, int] = {s.key: s.max_severity for s in DEFAULT_SOURCES if s.max_severity < 4}
