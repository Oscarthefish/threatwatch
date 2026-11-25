"""Threat Landscapes: assessment rules, change tracking, API safety and knowledge-base integrity.

All organisations, products, headlines and claims are SYNTHETIC.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import jdumps, now_iso
from app.ingest import pipeline, sources
from app.landscape import engine, kb
from app.landscape import kb_response as R

NOW = datetime.now(timezone.utc)
H = {"X-TW-Request": "1"}


@pytest.fixture
def srcs(conn):
    pipeline.sync_sources(conn)
    keys = ["bleepingcomputer", "the-record", "cisa-advisories", "ncsc-nz", "huntress"]
    return {k: pipeline._source_dict(conn.execute("SELECT * FROM sources WHERE key=?", (k,)).fetchone()) for k in keys}


def article(conn, src, title, days=1, summary="SYNTHETIC summary."):
    aid = pipeline.store_item(conn, src, sources.RawItem(
        url=f"https://example.com/{abs(hash((src['key'], title)))}", title=title, summary_text=summary, published_at=NOW - timedelta(days=days)))
    pipeline.process_article(conn, aid)
    return aid


def attack_fixture(conn):
    conn.execute("INSERT INTO attack_tactics VALUES('TA0001','initial-access','Initial Access',0,'https://attack.mitre.org/tactics/TA0001')")
    conn.execute("INSERT INTO attack_tactics VALUES('TA0112','defense-impairment','Defense Impairment',1,'https://attack.mitre.org/tactics/TA0112')")
    for tid, name, tac in [("T1190", "Exploit Public-Facing Application", "initial-access"), ("T1133", "External Remote Services", "initial-access"),
                           ("T1685", "Disable or Modify Tools", "defense-impairment"), ("T1566", "Phishing", "initial-access")]:
        conn.execute("INSERT INTO attack_techniques(attack_id, stix_id, name, tactics, url) VALUES(?,?,?,?,?)",
                     (tid, f"attack-pattern--{tid}", name, jdumps([tac]), f"https://attack.mitre.org/techniques/{tid}/"))
    conn.execute("INSERT INTO attack_revoked VALUES('T1562','T1685')")
    conn.execute("INSERT INTO attack_mitigations VALUES('M1051','Update Software','Patch.','https://attack.mitre.org/mitigations/M1051')")
    conn.execute("INSERT INTO attack_links VALUES('M1051','mitigates','T1190')")
    conn.execute("INSERT INTO settings(key, value) VALUES('attack_version', '\"99.0\"')")


def profile(conn, kind="industry", name="SYNTHETIC NZ healthcare", sector="healthcare", countries=("NZ",), terms=(), domain=None):
    n = now_iso()
    cur = conn.execute("INSERT INTO profiles(kind, name, sector, countries, match_terms, domain, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (kind, name, sector, jdumps(list(countries)), jdumps(list(terms)), domain, n, n))
    return cur.lastrowid


def fact(conn, pid, category, value, subtype="", status="", provenance="user"):
    n = now_iso()
    conn.execute("INSERT INTO profile_facts(profile_id, category, subtype, value, status, provenance, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                 (pid, category, subtype, value, status, provenance, n, n))


def kev(conn, cve, vendor, product, days=5, ransomware="Unknown", cvss=9.8, epss=0.4, in_kev=True):
    n = now_iso()
    conn.execute("""INSERT INTO vulnerabilities(cve_id, vendor, product, name, kev, kev_date_added, kev_ransomware, cvss_score, epss, first_seen_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                 (cve, vendor, product, f"{vendor} {product} flaw", int(in_kev), (NOW - timedelta(days=days)).strftime("%Y-%m-%d") if in_kev else None,
                  ransomware, cvss, epss, n, n))


def claim(conn, i, group="SYNTHETIC Locker", victim="Example Clinic", sector="Healthcare", country="NZ", days=3, domain=None):
    t = (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conn.execute("""INSERT INTO ransomware_claims(record_url, group_raw, group_name, victim, domain, country, sector, discovered_at, retrieved_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""", (f"https://www.ransomware.live/id/x{i}", group, group, victim, domain, country, sector, t, t))


def finding(result, key):
    return next((f for f in result["findings"] if f["key"] == key), None)


# ------------------------------------------------------------------ classification and priority
def test_without_evidence_threats_are_plausible_scenarios_only(conn, srcs):
    pid = profile(conn)
    r = engine.assess(conn, pid)
    rw = finding(r, "threat:ransomware")
    assert rw["classification"] == "plausible" and rw["priority"]["code"] >= "P3"
    assert rw["confidence"]["level"] == "none" and "not evidence of an active campaign" in rw["summary"]
    assert not finding(r, "threat:ddos") and not finding(r, "threat:insider")      # evidence-only categories stay out
    assert any("preventive controls" in u for u in rw["unknowns"])                  # unknown controls are unknown, never "missing"
    assert not any("missing" in u.lower() for f in r["findings"] for u in f["unknowns"])


def test_sector_reporting_and_claims_make_a_threat_observed(conn, srcs):
    pid = profile(conn)
    article(conn, srcs["the-record"], "Ransomware gang hits SYNTHETIC hospital network, patients diverted", days=3)
    for i in range(12):
        claim(conn, i)
    rw = finding(engine.assess(conn, pid), "threat:ransomware")
    assert rw["classification"] == "observed" and rw["priority"] == {"code": "P2", "label": "High", "points": 5}  # 2 sector + 2 claims + 1 local claims
    factors = {f["factor"]: f for f in rw["factors"]}
    assert factors["Sector-specific reporting"]["points"] == 2 and "Leak-site claims against the sector" in factors
    assert "unverified" in factors["Leak-site claims against the sector"]["basis"]
    assert rw["evidence"][0]["matched"] == ["sector term “hospital” in headline"]
    assert rw["claims"]["count"] == 12 and rw["claims"]["in_countries"] == 12
    assert any(t["id"] == "T1133" and "guidance" in t["basis"] for t in rw["techniques"])


def test_old_reporting_is_historical_not_active(conn, srcs):
    pid = profile(conn)
    article(conn, srcs["the-record"], "Phishing campaign targeted SYNTHETIC hospital staff", days=70)
    ph = finding(engine.assess(conn, pid), "threat:phishing")
    assert ph["classification"] == "historical" and ph["priority"]["code"] >= "P3"


def test_vulnerability_advisories_are_not_threat_activity(conn, srcs):
    pid = profile(conn, sector="manufacturing")
    article(conn, srcs["cisa-advisories"], "SYNTHETIC Controls PLC firmware", days=2,
            summary="Critical infrastructure sectors: Manufacturing. Successful exploitation could cause a denial-of-service condition.")
    r = engine.assess(conn, pid)
    assert not finding(r, "threat:ddos")
    assert all(not f["evidence"] for f in r["findings"])


def test_country_needs_headline_or_national_source(conn, srcs):
    pid = profile(conn, sector=None)
    article(conn, srcs["bleepingcomputer"], "Phishing kit spreads worldwide", summary="Victims include firms in New Zealand and elsewhere.")
    article(conn, srcs["ncsc-nz"], "Phishing campaign impersonating a government agency")
    ev = finding(engine.assess(conn, pid), "threat:phishing")["evidence"]
    assert [e["source"] for e in ev] == ["NCSC New Zealand alerts"]


def test_kev_matches_listed_technology_only(conn, srcs):
    pid = profile(conn, kind="organisation", name="SYNTHETIC Devices Ltd", sector="manufacturing")
    fact(conn, pid, "tech", "Citrix NetScaler Gateway", "internet_facing")
    fact(conn, pid, "tech", "Microsoft 365", "email")
    fact(conn, pid, "tech", "Fortinet FortiGate", "network")
    kev(conn, "CVE-2099-0001", "Citrix", "NetScaler", ransomware="Known")
    kev(conn, "CVE-2099-0002", "Microsoft", "Windows")
    kev(conn, "CVE-2099-0003", "Fortinet", "Multiple Products")
    kev(conn, "CVE-2099-0004", "Citrix", "NetScaler", days=400)                     # outside the window
    kev(conn, "CVE-2099-0005", "Citrix", "NetScaler", in_kev=False, cvss=10.0)     # CVSS 10 but no exploitation evidence
    r = engine.assess(conn, pid)
    ns = finding(r, "kev:citrix netscaler gateway")
    assert [v["cve_id"] for v in ns["vulnerabilities"]] == ["CVE-2099-0001"]
    assert ns["classification"] == "observed" and ns["priority"]["code"] == "P1"
    assert {f["factor"] for f in ns["factors"]} >= {"Active exploitation", "Internet-facing", "Known ransomware use"}
    assert any("Versions in use" in u for u in ns["unknowns"])
    assert not finding(r, "kev:microsoft 365")                                       # Windows KEV is not Microsoft 365
    fg = finding(r, "kev:fortinet fortigate")
    assert fg["vulnerabilities"][0]["match"].startswith("vendor only") and "KEV names only the vendor" in fg["unknowns"][0]


def test_product_aliases(conn):
    assert engine._tech_match("Fortinet FortiGate 100F", "Fortinet", "FortiOS") == "product"
    assert engine._tech_match("Palo Alto GlobalProtect", "Palo Alto Networks", "PAN-OS") is None   # vendor name must match
    assert engine._tech_match("Palo Alto Networks GlobalProtect", "Palo Alto Networks", "PAN-OS") == "product"
    assert engine._tech_match("Ivanti Endpoint Manager", "Ivanti", "Connect Secure") is None


def test_organisation_reporting_and_unverified_claims(conn, srcs):
    pid = profile(conn, kind="organisation", name="Kowhai & Rata Medical", sector="healthcare", domain="kowhairata.example")
    article(conn, srcs["the-record"], "Kowhai and Rata Medical confirms unauthorised access to staff email", days=4)
    claim(conn, 1, victim="Other Clinic", domain="kowhairata.example")
    r = engine.assess(conn, pid)
    org = finding(r, "org-reporting")
    assert org and org["evidence"][0]["matched"] == ["names “Kowhai and Rata Medical”"]
    assert "does not confirm a compromise" in org["summary"]
    oc = finding(r, "org-claims")
    assert oc and "not verified" in oc["summary"] and oc["confidence"]["level"] == "low"


def test_tested_controls_lower_priority_with_a_stated_reason(conn, srcs):
    pid = profile(conn)
    for i in range(12):
        claim(conn, i)
    before = finding(engine.assess(conn, pid), "threat:ransomware")["priority"]["points"]
    fact(conn, pid, "control", "Immutable backups, restore tested in October", "hard_backup", "implemented_tested")
    after = finding(engine.assess(conn, pid), "threat:ransomware")
    assert after["priority"]["points"] == before - 1
    assert any(f["factor"] == "Controls reported as implemented and tested" and f["points"] == -1 for f in after["factors"])


def test_revoked_attack_ids_resolve(conn, srcs):
    attack_fixture(conn)
    att = engine.Attack(conn)
    assert att.resolve("T1562") == ("T1685", "T1562 was replaced by T1685 in ATT&CK")
    assert att.resolve("T1190.001")[0] == "T1190"
    assert att.resolve("T9999")[1] == "not found in the loaded ATT&CK release"


# ------------------------------------------------------------------ snapshots and change tracking
def test_unchanged_inputs_do_not_create_snapshots_and_changes_are_explained(conn, srcs):
    pid = profile(conn, kind="organisation", name="SYNTHETIC Devices Ltd", sector="manufacturing")
    fact(conn, pid, "tech", "Citrix NetScaler Gateway", "internet_facing")
    first = engine.run(conn, pid)
    assert first["changes"]["first"] is True
    assert engine.run(conn, pid)["unchanged"] is True
    kev(conn, "CVE-2099-0001", "Citrix", "NetScaler")
    article(conn, srcs["bleepingcomputer"], "Ransomware attack halts SYNTHETIC factory production lines", days=1)
    ch = engine.run(conn, pid)["changes"]
    assert "kev:citrix netscaler gateway" in ch["new"]
    assert any(s.startswith("1 new finding") for s in ch["summary"])
    assert any("Priority raised: Ransomware" in s or "Ransomware and data extortion: plausible to observed" in s for s in ch["summary"])
    assert conn.execute("SELECT COUNT(*) FROM assessments WHERE profile_id=?", (pid,)).fetchone()[0] == 2


# ------------------------------------------------------------------ API
@pytest.fixture
def client(conn, srcs):
    from app.auth import hash_password
    from app.main import create_app
    conn.execute("INSERT INTO users(username, password_hash) VALUES('analyst', ?)", (hash_password("correct horse battery staple"),))
    c = TestClient(create_app())
    return c


def login(c):
    assert c.post("/api/auth/login", json={"username": "analyst", "password": "correct horse battery staple"}).status_code == 200


def test_landscape_api_requires_auth(client):
    for path in ["/api/landscapes", "/api/landscapes/meta", "/api/landscapes/1", "/api/landscapes/1/attack", "/api/landscapes/1/export.md"]:
        assert client.get(path).status_code == 401, path
    assert client.post("/api/landscapes", json={"kind": "industry", "name": "x"}).status_code in (401, 403)


def test_end_to_end_workflow(client, conn):
    login(client)
    attack_fixture(conn)
    r = client.post("/api/landscapes", headers=H, json={"kind": "organisation", "name": "SYNTHETIC Devices Ltd", "sector": "manufacturing",
                                                         "countries": ["nz"], "domain": "https://devices.example/about"})
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    other = client.post("/api/landscapes", headers=H, json={"kind": "industry", "name": "Other"}).json()["id"]
    p = client.get(f"/api/landscapes/{pid}").json()["profile"]
    assert p["countries"] == ["NZ"] and p["domain"] == "devices.example"

    # facts: provenance rules and URL safety
    assert client.post(f"/api/landscapes/{pid}/facts", headers=H, json={"category": "context", "value": "Makes devices", "provenance": "public"}).status_code == 422
    assert client.post(f"/api/landscapes/{pid}/facts", headers=H, json={"category": "context", "value": "x", "provenance": "public",
                                                                       "source_url": "javascript:alert(1)"}).status_code == 422
    fid = client.post(f"/api/landscapes/{pid}/facts", headers=H, json={"category": "tech", "subtype": "internet_facing", "value": "Citrix NetScaler Gateway"}).json()["id"]
    assert client.put(f"/api/landscapes/{other}/facts/{fid}", headers=H, json={"category": "tech", "subtype": "os", "value": "x"}).status_code == 404
    assert client.delete(f"/api/landscapes/{other}/facts/{fid}", headers=H).status_code == 404

    assert client.get(f"/api/landscapes/{pid}/attack").status_code == 409              # needs an assessment
    kev(conn, "CVE-2099-0001", "Citrix", "NetScaler")
    run = client.post(f"/api/landscapes/{pid}/assess", headers=H).json()
    assert run["changes"]["first"]
    full = client.get(f"/api/landscapes/{pid}").json()
    assert full["assessment"]["findings"][0]["key"] == "kev:citrix netscaler gateway"

    m = client.get(f"/api/landscapes/{pid}/attack").json()
    cells = {c["id"]: c for t in m["tactics"] for c in t["techniques"]}
    assert cells["T1190"]["detection"] == "unknown" and m["attack_version"] == "99.0"
    d = client.get(f"/api/landscapes/{pid}/attack/T1190").json()
    assert d["mitigations"][0]["attack_id"] == "M1051" and d["profile"]["findings"]
    assert client.put(f"/api/landscapes/{pid}/coverage/T0000", headers=H, json={"detection": "validated"}).status_code == 404
    assert client.put(f"/api/landscapes/{pid}/coverage/T1190", headers=H, json={"telemetry": "available", "detection": "implemented"}).status_code == 200
    cov = client.get(f"/api/landscapes/{pid}/coverage").json()
    assert next(b for b in cov["backlog"] if b["id"] == "T1190")["step"] == "Test the detection"

    layer = client.get(f"/api/landscapes/{pid}/navigator")
    assert layer.headers["content-disposition"].startswith("attachment")
    L = layer.json()
    assert L["versions"] == {"attack": "99", "navigator": "5.1.0", "layer": "4.5"} and L["domain"] == "enterprise-attack"
    assert all(re.match(r"^T\d{4}(\.\d{3})?$", t["techniqueID"]) for t in L["techniques"])
    assert "not evidence of activity against the organisation" in L["description"]

    # dismissing needs a reason and hides the finding from the views
    key = "threat:ransomware"
    assert client.put(f"/api/landscapes/{pid}/reviews/{key}", headers=H, json={"decision": "dismissed"}).status_code == 422
    assert client.put(f"/api/landscapes/{pid}/reviews/{key}", headers=H, json={"decision": "dismissed", "reason": "Covered elsewhere"}).status_code == 200
    defend = client.get(f"/api/landscapes/{pid}/defend").json()
    assert all(key not in [x["key"] for x in m["findings"]] for m in defend["monitoring"])
    assert all(q["status"] == "conceptual" for m in defend["monitoring"] for q in m["queries"])
    assert all(h["status"] == "unknown" for h in defend["hardening"])

    # hunts: closing needs a conclusion
    hid = client.post(f"/api/landscapes/{pid}/hunts", headers=H, json={"template": "hunt_edge", "finding_key": "kev:citrix netscaler gateway"}).json()["id"]
    hunt = client.get(f"/api/landscapes/{pid}/hunts/{hid}").json()
    assert hunt["plan"]["finding"]["priority"] == "P1" and hunt["status"] == "proposed"
    assert client.patch(f"/api/landscapes/{pid}/hunts/{hid}", headers=H, json={"status": "completed"}).status_code == 422
    assert client.patch(f"/api/landscapes/{pid}/hunts/{hid}", headers=H, json={"status": "completed", "conclusion": "Nothing found in 30 days of VPN logs",
                                                                               "limitations": "Appliance logs only kept 30 days"}).status_code == 200
    assert client.get(f"/api/landscapes/{other}/hunts/{hid}").status_code == 404

    # readiness: no score from too few answers
    rd = client.get(f"/api/landscapes/{pid}/readiness").json()
    sc = next(s for s in rd["scenarios"] if s["scenario"] == "account_compromise")
    assert sc["score"] is None and sc["answered"] == 0
    client.put(f"/api/landscapes/{pid}/readiness/ir_team", headers=H, json={"answer": "tested", "evidence": "IR plan v3"})
    assert next(s for s in client.get(f"/api/landscapes/{pid}/readiness").json()["scenarios"] if s["scenario"] == "account_compromise")["score"] is None
    for k in R.questions_for("account_compromise"):
        client.put(f"/api/landscapes/{pid}/readiness/{k}", headers=H, json={"answer": "implemented"})
    sc = next(s for s in client.get(f"/api/landscapes/{pid}/readiness").json()["scenarios"] if s["scenario"] == "account_compromise")
    assert sc["score"] == 75

    # playbook: blanks instead of invented contacts, versioned edits, export
    bid = client.post(f"/api/landscapes/{pid}/playbooks", headers=H, json={"scenario": "account_compromise"}).json()["id"]
    pb = client.get(f"/api/landscapes/{pid}/playbooks/{bid}").json()
    assert "Incident lead: **[to complete]**" in pb["body"] and "Threat Watch never runs them" in pb["body"]
    assert "Citrix NetScaler Gateway" in pb["body"]
    assert client.patch(f"/api/landscapes/{pid}/playbooks/{bid}", headers=H, json={"body": pb["body"] + "\nEdited."}).json()["version"] == 2
    assert client.get(f"/api/landscapes/{pid}/playbooks/{bid}/versions/1").json()["body"] == pb["body"]
    assert client.get(f"/api/landscapes/{other}/playbooks/{bid}").status_code == 404

    # exercise: reference points appear only after moving on
    eid = client.post(f"/api/landscapes/{pid}/exercises", headers=H, json={"scenario": "account_compromise"}).json()["id"]
    ex = client.get(f"/api/landscapes/{pid}/exercises/{eid}").json()
    assert len(ex["spec"]["stages"]) == 1 and "points" not in ex["spec"]["stages"][0]["questions"][0]
    assert "SIMULATED" in ex["spec"]["setting"]
    client.patch(f"/api/landscapes/{pid}/exercises/{eid}", headers=H, json={"responses": {"s1_first": {"answer": "Call the user"}}, "advance": True})
    ex = client.get(f"/api/landscapes/{pid}/exercises/{eid}").json()
    assert len(ex["spec"]["stages"]) == 2 and "points" in ex["spec"]["stages"][0]["questions"][0]
    assert ex["responses"]["s1_first"]["answer"] == "Call the user"

    # interview preparation and Markdown export
    prep = client.post(f"/api/landscapes/{pid}/interview", headers=H, json={"role": "Senior Cyber Security Analyst"}).json()["id"]
    iv = client.get(f"/api/landscapes/{pid}/interview").json()
    keys = [q["key"] for q in iv["preps"][0]["questions"]]
    assert "iq_coordinate" in keys and "iq_identity" in keys
    client.put(f"/api/landscapes/{pid}/interview/{prep}/answers/iq_identity", headers=H,
               json={"answer": "Start with the user.", "covered": ["Confirm with the user out of band", "made up point"], "confidence": "ok"})
    q = next(q for q in client.get(f"/api/landscapes/{pid}/interview").json()["preps"][0]["questions"] if q["key"] == "iq_identity")
    assert q["covered"] == ["Confirm with the user out of band"] and q["revise"] is True
    md = client.get(f"/api/landscapes/{pid}/export.md?prep={prep}")
    assert md.headers["content-type"].startswith("text/markdown")
    assert "**not** findings about the company's security" in md.text and "[x] Confirm with the user out of band" in md.text

    assert client.delete(f"/api/landscapes/{pid}", headers=H).status_code == 200
    assert conn.execute("SELECT COUNT(*) FROM hunts").fetchone()[0] == 0                # cascades


# ------------------------------------------------------------------ knowledge base integrity
def test_knowledge_base_references_are_consistent():
    tid = re.compile(r"^T\d{4}(\.\d{3})?$")
    for k, t in kb.THREATS.items():
        assert all(m in kb.MONITORING for m in t["monitoring"]), k
        assert all(h in kb.HUNTS for h in t["hunts"]), k
        assert all(x in kb.HARDENING for x in t["hardening"]), k
        assert all(s in R.SCENARIOS for s in t["scenarios"]), k
        assert all(tid.match(x) for x in t["techniques"]), k
    for m in kb.MONITORING.values():
        assert all(x in kb.TELEMETRY for x in m["telemetry"]) and all(tid.match(x) for x in m["techniques"])
        assert set(m["queries"]) <= {"splunk", "sentinel", "xdr"}
    for h in kb.HUNTS.values():
        assert all(x in kb.TELEMETRY for x in h["telemetry"])
    for x in kb.HARDENING.values():
        assert all(c in kb.CIS_NAMES for c in x["cis"]) and all(c in kb.CSF_NAMES for c in x["csf"])
        assert all(re.match(r"^M\d{4}$", m) for m in x["mitigations"])
    for q in R.QUESTIONS.values():
        assert q["area"] in R.AREAS and (q["scenarios"] == R.ALL or all(s in R.SCENARIOS for s in q["scenarios"]))
    for pb in R.PLAYBOOKS.values():
        assert all(k in kb.TELEMETRY for k in pb["telemetry"]) and all(tid.match(x) for x in pb["progression"])
    # revoked in ATT&CK v20 (Impair Defenses and Impersonation moved); the knowledge base must use the current IDs
    used = {x for t in kb.THREATS.values() for x in t["techniques"]} | {x for m in kb.MONITORING.values() for x in m["techniques"]}
    assert not used & {"T1562", "T1562.001", "T1562.008", "T1070.001", "T1656"}
    text = json.dumps([kb.MONITORING, kb.HUNTS, kb.HARDENING, R.QUESTIONS, R.PLAYBOOKS, R.EXERCISES, R.INTERVIEW], ensure_ascii=False)
    assert "—" not in text                                                              # house style: no em dashes in UI copy


def test_court_follow_ups_are_not_current_targeting(conn, srcs):
    pid = profile(conn)
    article(conn, srcs["the-record"], "Ransomware suspect who hit SYNTHETIC hospital extradited to US", days=2)
    assert not finding(engine.assess(conn, pid), "threat:ransomware")["evidence"]


def test_case_study_seed_keeps_unknowns_unknown(conn, srcs):
    from app.landscape import casestudy
    pid = casestudy.seed(conn)
    assert casestudy.seed(conn) == pid                                                # idempotent
    facts = conn.execute("SELECT * FROM profile_facts WHERE profile_id=?", (pid,)).fetchall()
    assert all(f["source_url"] for f in facts if f["provenance"] == "public")
    assert any(f["provenance"] == "unknown" and "gained access" in f["value"] for f in facts)
    r = engine.assess(conn, pid)
    assert not any(x["factor"] == "Relevant technology listed" for f in r["findings"] for x in f["factors"])
    assert not finding(r, "org-reporting")                                             # nothing collected names it in this test data
    pb = conn.execute("SELECT body FROM playbooks WHERE profile_id=?", (pid,)).fetchone()[0]
    assert "[to complete]" in pb and "Fisher & Paykel Healthcare" in pb


def test_sourced_public_facts_about_the_organisation_count_as_evidence(conn, srcs):
    pid = profile(conn, kind="organisation", name="SYNTHETIC Devices Ltd", sector="manufacturing")
    assert finding(engine.assess(conn, pid), "threat:bec")["classification"] == "plausible"
    n = now_iso()
    conn.execute("""INSERT INTO profile_facts(profile_id, category, value, provenance, source_url, created_at, updated_at)
                    VALUES(?, 'context', 'Disclosed unauthorised access to employee email accounts', 'public', 'https://example.com/statement', ?, ?)""", (pid, n, n))
    conn.execute("""INSERT INTO profile_facts(profile_id, category, value, provenance, created_at, updated_at)
                    VALUES(?, 'context', 'Ransomware data leak site rumour', 'inferred', ?, ?)""", (pid, n, n))
    r = engine.assess(conn, pid)
    bec = finding(r, "threat:bec")
    assert bec["classification"] == "observed" and bec["profile_evidence"][0]["source_url"] == "https://example.com/statement"
    assert bec["confidence"]["level"] == "medium"
    assert not finding(r, "threat:ransomware")["profile_evidence"]                     # inferred facts are not evidence


def test_negated_statements_are_not_evidence(conn):
    assert engine._affirmative("Access to email accounts; no impact to products or supply chain; no evidence of ransomware") .strip().startswith("Access to email accounts")
    assert "ransomware" not in engine._affirmative("no evidence of ransomware or malware")
