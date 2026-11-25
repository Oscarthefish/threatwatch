"""Seed registry of recurring intelligence report series.

These are starting points, not verified integrations. Every seeded series starts disabled, with no page URL
and verified_at unset: a person confirms the official publication page, the report's actual name and its
frequency before discovery is switched on (Phase 4). The frequency here is the expected one from the brief,
shown as unverified in the UI. Nothing in this file is fetched.
"""
from __future__ import annotations

import sqlite3
from typing import NamedTuple

from ..db import now_iso

FREQUENCIES = ("annual", "semiannual", "quarterly", "monthly", "weekly", "irregular", "unknown")
CATEGORIES = {
    "frontline": "Operational and frontline",
    "landscape": "Threat landscape and industry",
    "specialist": "Specialist",
    "government": "Regional and government",
}
REGIONS = ("GLOBAL", "NZ", "AU", "APAC", "US", "UK", "EU")


class Seed(NamedTuple):
    key: str
    publisher: str
    series: str
    frequency: str
    category: str
    region: str
    priority: int
    notes: str = ""


SEEDS: list[Seed] = [
    # Priority 1: operational security and frontline intelligence
    Seed("sentinelone-annual", "SentinelOne", "Annual Threat Report", "annual", "frontline", "GLOBAL", 1),
    Seed("redcanary-tdr", "Red Canary", "Threat Detection Report", "annual", "frontline", "GLOBAL", 1,
         "Red Canary's blog is already collected as a news source."),
    Seed("mandiant-mtrends", "Google Cloud / Mandiant", "M-Trends", "annual", "frontline", "GLOBAL", 1,
         "Google Threat Intelligence's blog is already collected as a news source."),
    Seed("crowdstrike-gtr", "CrowdStrike", "Global Threat Report", "annual", "frontline", "GLOBAL", 1),
    Seed("crowdstrike-hunting", "CrowdStrike", "Threat Hunting Report", "annual", "frontline", "GLOBAL", 1),
    Seed("unit42-ir", "Palo Alto Networks Unit 42", "Global Incident Response Report", "annual", "frontline", "GLOBAL", 1,
         "Unit 42's blog is already collected as a news source."),
    Seed("talos-ir-trends", "Cisco Talos", "Incident Response Trends", "quarterly", "frontline", "GLOBAL", 1),
    Seed("sophos-active-adversary", "Sophos", "Active Adversary Report", "irregular", "frontline", "GLOBAL", 1),
    Seed("expel-threat-report", "Expel", "Threat Report", "irregular", "frontline", "GLOBAL", 1),
    Seed("microsoft-ddr", "Microsoft", "Digital Defense Report", "annual", "frontline", "GLOBAL", 1,
         "The Microsoft Security Blog is already collected as a news source."),
    # Priority 2: threat landscape and industry intelligence
    Seed("verizon-dbir", "Verizon", "Data Breach Investigations Report", "annual", "landscape", "GLOBAL", 2),
    Seed("ibm-xforce-index", "IBM", "X-Force Threat Intelligence Index", "annual", "landscape", "GLOBAL", 2),
    Seed("rapid7-landscape", "Rapid7", "Threat Landscape and Incident Response research", "irregular", "landscape", "GLOBAL", 2),
    Seed("fortiguard-landscape", "Fortinet / FortiGuard Labs", "Global Threat Landscape Report", "semiannual", "landscape", "GLOBAL", 2),
    Seed("kroll-spotlight", "Kroll", "Cyber Threat Intelligence Spotlight", "quarterly", "landscape", "GLOBAL", 2),
    Seed("nccgroup-ti", "NCC Group", "Threat Intelligence reports", "monthly", "landscape", "GLOBAL", 2),
    Seed("checkpoint-research", "Check Point Research", "Cyber threat and attack reports", "irregular", "landscape", "GLOBAL", 2),
    Seed("recordedfuture-research", "Recorded Future", "Annual and specialist threat research", "irregular", "landscape", "GLOBAL", 2),
    Seed("secureworks-research", "Secureworks", "Threat research", "irregular", "landscape", "GLOBAL", 2,
         "Check current availability; the publisher's research may have moved."),
    Seed("eset-threat-report", "ESET", "Threat Report", "semiannual", "landscape", "GLOBAL", 2),
    # Priority 3: specialist intelligence
    Seed("dragos-yir", "Dragos", "OT Cybersecurity Year in Review", "annual", "specialist", "GLOBAL", 3),
    Seed("zscaler-ransomware", "Zscaler ThreatLabz", "Ransomware Report", "annual", "specialist", "GLOBAL", 3),
    Seed("zscaler-phishing", "Zscaler ThreatLabz", "Phishing Report", "annual", "specialist", "GLOBAL", 3),
    Seed("gitguardian-secrets", "GitGuardian", "State of Secrets Sprawl", "annual", "specialist", "GLOBAL", 3),
    Seed("cloudflare-ddos", "Cloudflare", "DDoS Threat Report", "quarterly", "specialist", "GLOBAL", 3),
    Seed("proofpoint-research", "Proofpoint", "Phishing and human-centric threat research", "irregular", "specialist", "GLOBAL", 3),
    Seed("akamai-soti", "Akamai", "State of the Internet security reports", "irregular", "specialist", "GLOBAL", 3),
    Seed("mandiant-ai", "Mandiant", "AI security and threat research", "irregular", "specialist", "GLOBAL", 3),
    Seed("infostealers-reports", "Infostealers.com (Hudson Rock)", "Threat reports", "weekly", "specialist", "GLOBAL", 3,
         "Hudson Rock's research and weekly report feeds are already collected as news sources."),
    Seed("duo-trusted-access", "Cisco Duo", "Trusted Access research", "irregular", "specialist", "GLOBAL", 3),
    # Priority 4: regional and government intelligence
    Seed("ncsc-nz-annual", "NCSC New Zealand", "Annual Cyber Threat Report", "annual", "government", "NZ", 4),
    Seed("ncsc-nz-quarterly", "NCSC New Zealand", "Quarterly Cyber Security Insights", "quarterly", "government", "NZ", 4),
    Seed("asd-acsc-annual", "Australian Signals Directorate / ACSC", "Annual Cyber Threat Report", "annual", "government", "AU", 4),
    Seed("asd-advisories", "Australian Signals Directorate", "Cybersecurity advisories and research", "irregular", "government", "AU", 4,
         "ASD's ACSC alerts are already collected as a news source."),
    Seed("cisa-technical", "CISA", "Cybersecurity advisories and technical reports", "irregular", "government", "US", 4,
         "CISA advisories are already collected as a news source."),
    Seed("cisa-kev", "CISA", "Known Exploited Vulnerabilities catalogue", "irregular", "government", "US", 4,
         "Already collected daily by Threat Watch's KEV source; listed here for completeness only."),
    Seed("uk-ncsc-review", "UK NCSC", "Annual Review", "annual", "government", "UK", 4),
    Seed("enisa-landscape", "ENISA", "Threat Landscape", "annual", "government", "EU", 4),
    Seed("fbi-ic3", "FBI IC3", "Internet Crime Report", "annual", "government", "US", 4),
    Seed("europol-iocta", "Europol", "Internet Organised Crime Threat Assessment", "annual", "government", "EU", 4),
]


def sync(conn: sqlite3.Connection) -> int:
    """Insert seeds that are missing. Never overwrites a row a person has edited, and never re-adds one they deleted
    (deleted seed keys are remembered in settings)."""
    from ..db import get_setting

    removed = set(get_setting(conn, "report_sources_removed", []) or [])
    have = {r[0] for r in conn.execute("SELECT key FROM report_sources")}
    now = now_iso()
    n = 0
    for s in SEEDS:
        if s.key in have or s.key in removed:
            continue
        conn.execute(
            "INSERT INTO report_sources(key, publisher, series, frequency, category, region, priority, notes, seeded, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,1,?,?)",
            (s.key, s.publisher, s.series, s.frequency, s.category, s.region, s.priority, s.notes or None, now, now))
        n += 1
    return n
