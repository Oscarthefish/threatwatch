"""Fisher & Paykel Healthcare: the first worked case study for Threat Landscapes.

Every "public" fact below was checked on 25 November 2026 against its cited source: the company's NZX/ASX statement of
22 October 2026 (as published by BusinessDesk), or Chris Lynch Media's report of 23 November 2026 on the Falcon claim and
the company's response. Facts the statement does not give (how access was gained, who was responsible,
manufacturing locations, email platform) are recorded as unknown. Assessment dimensions such as the value of
intellectual property are recorded as inferred assumptions, never as facts about the company's security.

Note: "Fisher & Paykel" alone also names an unrelated appliance company, so the match terms always include "Healthcare".
"""
from __future__ import annotations

import sqlite3

from ..db import jdumps, now_iso
from . import engine

STATEMENT = "https://www.businessdesk.co.nz/nzx-announcements/fisher-paykel-healthcare-corporation/482175/"
STATEMENT_TITLE = "F&P Healthcare statement regarding cyber incident (NZX/ASX, 22 October 2026)"
CHECKED = "2026-11-25"
FALCON = "https://www.chrislynchmedia.com/news-items/fisher-paykel-healthcare-says-latest-cyber-crime-claim-relates-to-october-incident/"
FALCON_TITLE = "Fisher & Paykel Healthcare says latest cyber crime claim relates to October incident (Chris Lynch Media, 23 November 2026)"

PROFILE = {
    "kind": "organisation", "name": "Fisher & Paykel Healthcare", "sector": "healthcare", "countries": ["NZ", "AU"],
    "size": "large", "domain": "fphcare.com", "match_terms": ["Fisher and Paykel Healthcare", "F&P Healthcare", "Fisher & Paykel Healthcare Corporation"],
    "description": "Designer, manufacturer and marketer of products and systems for acute and chronic respiratory care, surgery and the "
                   "treatment of obstructive sleep apnea, sold in over 120 countries (company statement, 22 October 2026).",
}

# (category, subtype, value, status, provenance, note)
FACTS = [
    ("context", "", "Listed on the NZX and ASX (code FPH)", "", "public", ""),
    ("service", "", "Design and manufacture of medical devices (respiratory care, surgery, obstructive sleep apnea)", "", "public", ""),
    ("service", "", "Supply and support of hospitals, healthcare providers and patients in over 120 countries", "", "public", ""),
    ("context", "", "22 October 2026: disclosed unauthorised and unlawful access to two employee email accounts and a subset of company files", "", "public",
     "Statement: incident believed contained; response protocols activated; relevant authorities notified."),
    ("asset", "", "Personal information held in company files (some accessed files contained personally identifiable information)", "", "public",
     "Statement: the company is notifying those affected."),
    ("context", "", "Statement: no evidence the system that maintains patient data was compromised; no evidence of ransomware or malware; "
                    "no impact to products, manufacturing or supply chain", "", "public", "These are the company's statements at the time, not independent findings."),
    ("context", "", "How the attacker gained access to the email accounts", "", "unknown", "Not stated in the disclosure. Do not assume phishing or any other method."),
    ("context", "", "Who was responsible", "", "unknown",
     "Not stated by the company. A group calling itself Falcon claims the data (see below); the company has not confirmed it was responsible."),
    ("context", "", "23 November 2026: a group calling itself Falcon listed the company on its leak site, claiming 104.76 GB including device technical "
                    "and regulatory documents, commercial pricing, customer records and employee personal information", "", "public",
     "The group's own claim, reported by Chris Lynch Media and recorded by ransomware.live. Unverified: the company has not confirmed the data described.",
     FALCON, FALCON_TITLE),
    ("context", "", "Company response to the Falcon claim: \"Please refer to our 22 October announcement. This is related to the same incident.\"", "", "public",
     "The response did not confirm or deny Falcon's responsibility or the data it describes.", FALCON, FALCON_TITLE),
    ("tech", "email", "Email and collaboration platform", "", "unknown", "Not publicly stated. Add it if confirmed (for example in an interview)."),
    ("context", "", "Manufacturing and R&D locations", "", "unknown", "Not confirmed from a primary source in this assessment."),
    ("asset", "", "Product designs, research and regulatory documentation (intellectual property)", "", "inferred",
     "Assessment dimension: typical for a medical device designer. Not a statement about the company's systems."),
    ("asset", "", "Manufacturing availability for hospital and home-care products", "", "inferred",
     "Assessment dimension: a medical device manufacturer depends on continuous production and supply."),
    ("supplier", "", "Component suppliers, logistics providers and distributors", "", "inferred", "Assessment dimension; specific suppliers are not public in this assessment."),
    ("regulation", "", "Privacy and medical device regulatory obligations in each market", "", "unknown",
     "Which obligations apply and how is for the company's legal team; New Zealand's Privacy Act 2020 has notifiable breach rules."),
]


def seed(conn: sqlite3.Connection) -> int:
    """Create (or refresh) the case-study profile, assess it, and create the demonstration work items. Returns the profile id."""
    n = now_iso()
    row = conn.execute("SELECT id FROM profiles WHERE name=? AND kind='organisation'", (PROFILE["name"],)).fetchone()
    if row:
        pid = row[0]
        conn.execute("DELETE FROM profile_facts WHERE profile_id=?", (pid,))
    else:
        pid = conn.execute(
            """INSERT INTO profiles(kind, name, sector, countries, size, description, domain, match_terms, options, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (PROFILE["kind"], PROFILE["name"], PROFILE["sector"], jdumps(PROFILE["countries"]), PROFILE["size"], PROFILE["description"],
             PROFILE["domain"], jdumps(PROFILE["match_terms"]), jdumps(engine.DEFAULT_OPTIONS), n, n)).lastrowid
    for cat, sub, value, status, prov, note, *src in FACTS:
        public = prov == "public"
        url, title = src if src else (STATEMENT, STATEMENT_TITLE)
        conn.execute(
            """INSERT INTO profile_facts(profile_id, category, subtype, value, status, provenance, source_url, source_title, verified_at, note, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, cat, sub, value, status, prov, url if public else None, title if public else None, CHECKED if public else None, note, n, n))
    conn.execute("UPDATE profiles SET updated_at=? WHERE id=?", (n, pid))
    engine.run(conn, pid)
    a = conn.execute("SELECT findings FROM assessments WHERE profile_id=? ORDER BY id DESC LIMIT 1", (pid,)).fetchone()
    from ..db import jloads
    from . import kb, response
    findings = jloads(a[0])
    if not conn.execute("SELECT 1 FROM hunts WHERE profile_id=? AND template='hunt_mail_persistence'", (pid,)).fetchone():
        h = kb.HUNTS["hunt_mail_persistence"]
        f = next((x for x in findings if x.get("threat") in ("bec", "identity", "phishing")), None)
        plan = {**h, "telemetry": [{"key": k, "label": kb.TELEMETRY[k]["label"], "status": "unknown"} for k in h["telemetry"]],
                "intelligence": [{"title": STATEMENT_TITLE, "url": STATEMENT, "source": "NZX / BusinessDesk", "published_at": "2026-10-22"}],
                "finding": {"key": f["key"], "title": f["title"], "priority": f["priority"]["code"]} if f else None, "groups": [],
                "hypothesis": h["hypothesis"] + " (Practice hunt for interview preparation: the company has not said how its email accounts were accessed.)"}
        conn.execute("INSERT INTO hunts(profile_id, template, finding_key, title, plan, created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                     (pid, "hunt_mail_persistence", f["key"] if f else None, h["title"], jdumps(plan), n, n))
    if not conn.execute("SELECT 1 FROM playbooks WHERE profile_id=? AND scenario='account_compromise'", (pid,)).fetchone():
        p = engine.load_profile(conn, pid)
        title, md = response.draft_playbook(conn, p, "account_compromise", findings)
        bid = conn.execute("INSERT INTO playbooks(profile_id, scenario, title, body, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                           (pid, "account_compromise", title, md, n, n)).lastrowid
        conn.execute("INSERT INTO playbook_versions(playbook_id, version, body, saved_at) VALUES(?,?,?,?)", (bid, 1, md, n))
    if not conn.execute("SELECT 1 FROM interview_preps WHERE profile_id=?", (pid,)).fetchone():
        conn.execute("INSERT INTO interview_preps(profile_id, role, job_description, created_at, updated_at) VALUES(?,?,?,?,?)",
                     (pid, "Senior Cyber Security Analyst", "", n, n))
    return pid
