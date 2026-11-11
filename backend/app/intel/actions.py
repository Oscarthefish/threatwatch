"""SecOps next steps ("what should the SOC do?") derived from evidence.

Every action states its basis so guidance is never mistaken for reporting:
  * "CISA KEV"            – CISA's own required action and due date for a KEV-listed CVE
  * "CVE record / EPSS"   – scores from CVE.org / FIRST EPSS
  * "Source indicators"   – IOCs extracted verbatim from the article
  * "Source ATT&CK"       – technique IDs named in the article
  * "Playbook"            – standard SOC practice triggered by the type of threat
                            (general guidance, not a claim about this incident)
"""
from __future__ import annotations

import re

from . import entities as ent

ORDER = ["patch", "exposure", "hunt", "detect", "ransomware", "identity", "supply-chain", "track"]
SUPPLY = re.compile(r"supply[- ]chain|malicious (npm|pypi|package)|typosquat|dependency confusion|compromised (package|library|extension)", re.I)


def _a(kind, label, detail, basis, urgent=False):
    return {"kind": kind, "label": label, "detail": detail, "basis": basis, "urgent": urgent}


def derive(title: str, text: str, severity: int, tags: list[str], ents: dict[str, list[str]], vulns: list[dict]) -> list[dict]:
    """``ents`` maps entity type -> display values; ``vulns`` are vulnerabilities rows for mentioned CVEs."""
    out: list[dict] = []
    tags_s = set(tags)
    if "roundup" in tags_s:
        return []  # roundups/podcasts mix many stories; per-story guidance would be misleading

    kev = [v for v in vulns if v.get("kev")]
    if kev:
        def name(v):
            prod = " ".join(x for x in (v.get("vendor"), v.get("product")) if x)
            return f"{v['cve_id']}{f' ({prod})' if prod else ''}"
        dues = sorted(v["kev_due_date"] for v in kev if v.get("kev_due_date"))
        ransom = [v["cve_id"] for v in kev if v.get("kev_ransomware") == "Known"]
        lead = (f"{name(kev[0])} is exploited in the wild (CISA KEV)." if len(kev) == 1 else
                f"{len(kev)} CVEs here are exploited in the wild (CISA KEV): {'; '.join(name(v) for v in kev[:4])}{'; …' if len(kev) > 4 else ''}.")
        # CISA's text continues with BOD compliance boilerplate; keep the action itself (full wording is on the KEV entry).
        action = re.split(r"(?<=\.)\s|,\s*(?:ensuring|follow|per\b)|;\s", (kev[0].get("kev_required_action") or "Apply vendor updates").strip())[0].rstrip(".,")
        out.append(_a("patch", "Patch now",
                      f"{lead} CISA action: {action}."
                      + (f" US federal deadline {dues[0]}." if dues else "")
                      + (f" Known ransomware use: {', '.join(ransom)}." if ransom else ""),
                      "CISA KEV", urgent=True))
    others = [v for v in vulns if not v.get("kev") and ((v.get("cvss_score") or 0) >= 9 or (v.get("epss") or 0) >= 0.1
                                                         or "exploited" in tags_s)]
    if others:
        parts = []
        for v in others[:3]:
            bits = [f"CVSS {v['cvss_score']}" if v.get("cvss_score") is not None else "",
                    f"EPSS {v['epss'] * 100:.1f}%" if v.get("epss") is not None else ""]
            parts.append(f"{v['cve_id']} ({', '.join(b for b in bits if b) or 'scores pending'})")
        out.append(_a("patch", "Prioritise patching",
                      f"{'; '.join(parts)}{' and reported as exploited' if 'exploited' in tags_s else ''}. Apply the vendor fix or mitigation.",
                      "CVE record / EPSS", urgent="exploited" in tags_s))
    if not vulns and tags_s & {"exploited", "zero-day"} and "vulnerability" in tags_s:
        out.append(_a("patch", "Apply vendor update",
                      "The source reports exploitation of a vulnerability. Apply the vendor's update or published mitigation as soon as it is available.",
                      "Source (reported exploitation)", urgent=True))

    products = []
    for v in vulns:
        p = " ".join(x for x in (v.get("vendor"), v.get("product")) if x)
        if p and p not in products:
            products.append(p)
    products += [p for p in ents.get("product", []) if not any(p.lower() in q.lower() or q.lower() in p.lower() for q in products)]
    if products and (tags_s & {"vulnerability", "exploited", "zero-day", "exploitation-attempts"}):
        out.append(_a("exposure", "Check exposure",
                      f"Identify where {', '.join(products[:3])}{' and others' if len(products) > 3 else ''} {'is' if len(products) == 1 else 'are'} deployed and at which versions. Start with internet-facing and high-value systems.",
                      "Playbook", urgent=severity >= 3))

    iocs = [(t, v) for t in ent.IOC_TYPES for v in ents.get(t, [])]
    if iocs:
        kinds = sorted({t for t, _ in iocs})
        out.append(_a("hunt", "Hunt for indicators",
                      f"{len(iocs)} indicator{'s' if len(iocs) != 1 else ''} in the source ({', '.join(kinds)}). "
                      "Search DNS, proxy, firewall and EDR telemetry for the last 30 days, then block.",
                      "Source indicators", urgent=severity >= 3))

    explicit = [t for t in ents.get("attack_technique", [])]
    if explicit:
        named = [f"{t} {ent.technique_name(t) or ''}".strip() for t in explicit[:4]]
        out.append(_a("detect", "Check detections", f"Confirm detection coverage for {', '.join(named)}.", "Source ATT&CK"))
    elif "detection" in tags_s and ("soc-dfir" in tags_s or re.search(r"\b(sigma|splunk|kql|yara|detection rule|hunting quer)", text, re.I)):
        out.append(_a("detect", "Review detection content", "The source includes detection or hunting material. Compare it with your current rules.", "Source"))

    if "ransomware" in tags_s and severity >= 2:
        out.append(_a("ransomware", "Ransomware readiness",
                      "Check alerting for shadow copy deletion, mass file renames and new remote-access tools, and confirm offline backups are restorable.",
                      "Playbook"))
    if "phishing" in tags_s and severity >= 1:
        out.append(_a("identity", "Identity and users",
                      "Watch for matching lures and unusual sign-ins (impossible travel, new MFA devices). Consider a short user advisory.",
                      "Playbook"))
    vendors = set(ents.get("vendor", []))
    if SUPPLY.search(f"{title}\n{text}") or (vendors & {"npm", "PyPI"} and "malware" in tags_s):
        out.append(_a("supply-chain", "Check dependencies",
                      "Search lockfiles, build pipelines and developer machines for the packages or extensions named in the source.",
                      "Playbook", urgent=severity >= 3))
    actors = ents.get("actor", [])
    if actors and severity >= 2:
        out.append(_a("track", "Track actor", f"Follow {', '.join(actors[:2])} to collect further reporting and TTPs.", "Playbook"))

    out.sort(key=lambda x: (not x["urgent"], ORDER.index(x["kind"])))
    return out[:6]
