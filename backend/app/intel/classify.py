"""Section classification, severity, confidence and ranking.

All scoring is transparent: every severity adjustment records a human-readable
reason that is shown in the UI ("source-backed severity").
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_LABELS = ["info", "low", "medium", "high", "critical"]

SECTIONS = ["breaking", "threat-intel", "vulnerabilities", "soc-dfir", "nz-apac"]

_P = lambda s: re.compile(s, re.I)  # noqa: E731

EXPLOITED = _P(r"exploited in (attacks|the wild|zero-day attacks)|exploited (as a )?(zero[- ]day|flaw|bug|vulnerabilit)|exploited to (breach|hack|deploy|gain|compromise)|hackers? exploit|attackers? exploit|actively exploited|exploited in the wild|in-the-wild exploitation|under active (attack|exploitation)|exploited (as a )?zero[- ]day|mass exploitation|being exploited|exploitation (attempts|activity)")
ZERODAY = _P(r"\bzero[- ]day\b|\b0-?day\b")
EMERGENCY = _P(r"emergency (directive|patch|update)|out-of-band|critical (flaw|vulnerability|bug)|patch now|urgent")
SCANNING = _P(r"\bscan(s|ning)? for\b.*(vulnerab|CVE-|flaw|exploit)|exploitation attempts|honeypot")
MILLIONS = _P(r"\b\d+(\.\d+)? ?(million|m)\b (customers|users|people|patients|records|individuals|accounts)|\$\d+(\.\d+)? ?(million|billion)")
BREACH = _P(r"\b(data breach|breach(es|ed)?|heist|hackers? (stole|steal|breach|hit)|ransomware gang|ransomware attack|ransomware attack|cyberattack|cyber attack|hacked|hack of|outage|disrupt(ed|ion)|extortion|leak(ed)? data|stolen data|compromised)\b")
RANSOMWARE = _P(r"\bransomware\b")
PHISHING = _P(r"\bphishing\b|credential (theft|harvesting|phishing)|\bsmishing\b|\bvishing\b|infostealer|adversary-in-the-middle|\bAiTM\b|\bMFA bypass")
MALWARE = _P(r"\bmalware\b|\bbackdoor\b|\btrojan\b|\bbotnet\b|\bloader\b|\bstealer\b|\brootkit\b|\bspyware\b|\bwiper\b|\bRAT\b")
ACTOR = _P(r"threat actor|state-sponsored|nation-state|\bAPT\b|espionage|hacking group|cyber ?gang|hacktivist")
TTP = _P(r"initial access|persistence|lateral movement|privilege escalation|defense evasion|command and control|exfiltration|MITRE ATT&CK")
VULN = _P(r"\bvulnerabilit(y|ies)\b|\bCVE-\d{4}-\d+|\bpatch(es|ed)?\b|security update|\bflaw\b|\bbug\b|advisory|remote code execution|\bRCE\b|authentication bypass|privilege escalation")
SOC = _P(r"detection|threat hunt|hunting|\bsigma\b|\bsplunk\b|\bKQL\b|\bSPL\b|\bYARA\b|\bEDR\b|\bSIEM\b|forensic|DFIR|incident response|investigat(e|ion)|telemetry|sysmon|event log|playbook|triage|\bIOCs?\b|indicators of compromise|\bSOC\b|blue team")
ROUNDUP = _P(r"week in (review|ransomware|security)|weekly (recap|roundup|update)|newsletter|podcast|^risky (business|bulletin)|sponsored|webinar|\bdeal\b|% off|black friday|giveaway|how to (buy|save)")


@dataclass
class Classification:
    sections: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severity: int = 1
    reasons: list[str] = field(default_factory=list)
    region: str | None = None


def classify(
    title: str,
    text: str,
    source: dict,
    entity_types: dict[str, set[str]],
    vuln_facts: list[dict],
) -> Classification:
    """``entity_types`` maps type -> set of values; ``vuln_facts`` are vulnerabilities rows for mentioned CVEs."""
    c = Classification()
    full = f"{title}\n{text}"
    tags: set[str] = set()
    secs: set[str] = set(source.get("default_sections") or [])

    if RANSOMWARE.search(full) or entity_types.get("ransomware"):
        tags.add("ransomware")
    if MALWARE.search(full) or entity_types.get("malware"):
        tags.add("malware")
    if ACTOR.search(full) or entity_types.get("actor"):
        tags.add("threat-actor")
    if PHISHING.search(full):
        tags.add("phishing")
    if TTP.search(full) or entity_types.get("attack_technique"):
        tags.add("ttp")
    if VULN.search(title) or entity_types.get("cve"):
        tags.add("vulnerability")
    if SOC.search(full):
        tags.add("detection")
    if EXPLOITED.search(title) or EXPLOITED.search(text[:1500]):
        tags.add("exploited")
    if SCANNING.search(title):
        tags.add("exploitation-attempts")
    if ZERODAY.search(full):
        tags.add("zero-day")
    if BREACH.search(title):
        tags.add("incident")
    if ROUNDUP.search(title) or ROUNDUP.search(source.get("name", "")) and "podcast" in source.get("name", "").lower():
        tags.add("roundup")

    if tags & {"ransomware", "malware", "threat-actor", "phishing", "ttp"}:
        secs.add("threat-intel")
    if "vulnerability" in tags:
        secs.add("vulnerabilities")
    if "detection" in tags and (SOC.search(title) or "soc-dfir" in secs):
        secs.add("soc-dfir")
    regions = entity_types.get("region", set())
    if source.get("region") in ("NZ", "AU", "APAC") or regions & {"nz", "au", "apac"}:
        secs.add("nz-apac")
        c.region = source.get("region") if source.get("region") in ("NZ", "AU", "APAC") else (
            "NZ" if "nz" in regions else "AU" if "au" in regions else "APAC")

    # ------------------------------------------------------------ severity
    sev = 1
    reasons: list[str] = []
    kev = [v for v in vuln_facts if v.get("kev")]
    if kev:
        sev += 2
        reasons.append(f"{', '.join(v['cve_id'] for v in kev[:3])} listed in CISA KEV (confirmed exploitation)")
    if "exploited" in tags and not kev:
        sev += 2 if "vulnerability" in tags else 1
        reasons.append("Reporting describes active exploitation" + (" of a vulnerability" if "vulnerability" in tags else ""))
    if "exploitation-attempts" in tags and "exploited" not in tags and not kev:
        sev += 1
        reasons.append("Scanning / exploitation attempts observed")
    if "zero-day" in tags:
        sev += 1
        reasons.append("Zero-day referenced")
    crit = [v for v in vuln_facts if (v.get("cvss_score") or 0) >= 9.0]
    if crit:
        sev += 1
        reasons.append(f"CVSS {crit[0]['cvss_score']} ({crit[0]['cve_id']})")
    hi_epss = [v for v in vuln_facts if (v.get("epss") or 0) >= 0.5]
    if hi_epss and not kev:
        sev += 1
        reasons.append(f"EPSS {hi_epss[0]['epss']:.0%} exploitation probability ({hi_epss[0]['cve_id']})")
    if EMERGENCY.search(title):
        sev += 1
        reasons.append("Emergency / out-of-band language in headline")
    if "incident" in tags and ("ransomware" in tags or BREACH.search(title)):
        sev += 1
        reasons.append("Reported incident affecting an organisation")
        if MILLIONS.search(title):
            sev += 1
            reasons.append("Large-scale impact stated in headline")
    if source.get("authority", 2) >= 3 and source.get("kind") != "kev" and ("vulnerability" in tags or "exploited" in tags or "incident" in tags):
        sev += 1
        reasons.append(f"Official advisory ({source.get('name')})")
    if "roundup" in tags:
        sev -= 1
        reasons.append("Roundup / podcast / commentary format")
    if not reasons:
        reasons.append("General security reporting")
    c.severity = max(0, min(4, sev))
    c.reasons = reasons

    if c.severity >= 3 and ("exploited" in tags or "zero-day" in tags or "incident" in tags or kev):
        secs.add("breaking")
    c.tags = sorted(tags)
    c.sections = [s for s in SECTIONS if s in secs]
    return c


def confidence(source_authority: int, distinct_sources: int) -> str:
    if source_authority >= 3:
        return "official"
    if distinct_sources >= 3:
        return "corroborated"
    if distinct_sources == 2:
        return "multi-source"
    return "single-source"


def rank_score(severity: int, published: datetime | None, distinct_sources: int, region: str | None) -> float:
    age_h = 72.0
    if published:
        age_h = max(0.0, (datetime.now(timezone.utc) - published).total_seconds() / 3600)
    recency = 20.0 * math.exp(-age_h / 36.0)  # half-life ~25h
    return round(severity * 10 + recency + min(distinct_sources - 1, 4) * 3 + (4 if region == "NZ" else 2 if region in ("AU", "APAC") else 0), 3)
