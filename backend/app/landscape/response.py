"""Incident readiness scoring, playbook drafting and interview briefings, built from a profile and its latest assessment."""
from __future__ import annotations

import sqlite3
from datetime import date

from . import kb
from . import kb_response as R
from .engine import Attack

MIN_ANSWERED = 0.6  # a readiness score is shown only when this share of applicable questions has a real answer


def relevant_scenarios(findings: list[dict], dismissed: set[str]) -> list[dict]:
    """Scenarios linked to the findings, most important first; employee account compromise is always included."""
    best: dict[str, dict] = {}
    for f in findings:
        if f["key"] in dismissed:
            continue
        t = kb.THREATS.get(f.get("threat") or "")
        for s in (t["scenarios"] if t else []):
            cur = best.get(s)
            if not cur or f["priority"]["code"] < cur["priority"]:
                best[s] = {"key": s, "priority": f["priority"]["code"], "because": f["title"], "classification": f["classification"]}
    best.setdefault("account_compromise", {"key": "account_compromise", "priority": "P3", "because": "Common to almost every organisation",
                                           "classification": "plausible"})
    out = sorted(best.values(), key=lambda x: (x["priority"], x["key"]))
    for s in out:
        s.update(R.SCENARIOS[s["key"]])
    return out


def readiness(conn: sqlite3.Connection, pid: int, scenarios: list[dict]) -> dict:
    answers = {r["question"]: dict(r) for r in conn.execute("SELECT * FROM readiness_answers WHERE profile_id=?", (pid,))}
    out = []
    plan: dict[str, dict] = {}
    for s in scenarios:
        qs = R.questions_for(s["key"])
        items, total, counted = [], 0.0, 0
        for k in qs:
            q = R.QUESTIONS[k]
            a = answers.get(k, {})
            ans = a.get("answer", "unknown")
            weight = R.ANSWERS[ans][1]
            if weight is not None:
                total += weight
                counted += 1
            items.append({"key": k, **q, "area_label": R.AREAS[q["area"]], "answer": ans, "evidence": a.get("evidence", ""), "updated_at": a.get("updated_at")})
            if ans in ("not_implemented", "partial", "unknown", "implemented"):
                if ans == "implemented" and not q["critical"]:
                    continue
                e = plan.setdefault(k, {"key": k, "text": q["text"], "why": q["why"], "improve": q["improve"], "owner": q["owner"],
                                        "critical": q["critical"], "answer": ans, "scenarios": [], "refs": q["refs"]})
                e["scenarios"].append(s["title"])
        applicable = len([i for i in items if i["answer"] != "na"])
        answered = counted
        score = round(100 * total / counted) if counted and answered >= MIN_ANSWERED * applicable else None
        out.append({"scenario": s["key"], "title": s["title"], "priority": s["priority"], "because": s["because"], "questions": items,
                    "answered": answered, "applicable": applicable, "score": score,
                    "unknown": len([i for i in items if i["answer"] == "unknown"]),
                    "gaps": len([i for i in items if i["answer"] in ("not_implemented", "partial")])})
    rank = {"not_implemented": 0, "partial": 1, "implemented": 2, "unknown": 3}
    improvements = sorted(plan.values(), key=lambda e: (rank[e["answer"]], not e["critical"], -len(e["scenarios"])))
    for e in improvements:
        e["action"] = ("Find out: " if e["answer"] == "unknown" else "Test: " if e["answer"] == "implemented" else "") + e["improve"]
        e["validate"] = "Record evidence (a document, test result or screenshot) in the answer and mark it implemented and tested."
    return {"scenarios": out, "improvements": improvements, "answers": R.ANSWERS, "areas": R.AREAS,
            "score_note": f"Scores use only your own answers; Unknown and Not applicable are left out, and no score is shown until at least "
                          f"{int(MIN_ANSWERED * 100)}% of a scenario's questions have an answer. Public information is never used to score readiness."}


# ------------------------------------------------------------------ playbooks
def _tel_line(profile: dict, key: str) -> str:
    st = next((f["status"] for f in profile["facts"] if f["category"] == "telemetry" and f["subtype"] == key), "") or "unknown"
    label = {"available": "available", "partial": "partly available", "not_available": "NOT available", "unknown": "availability not recorded"}[st]
    return f"- {kb.TELEMETRY[key]['label']} ({label}): {kb.TELEMETRY[key]['detail']}"


def draft_playbook(conn: sqlite3.Connection, profile: dict, scenario: str, findings: list[dict]) -> tuple[str, str]:
    att = Attack(conn)
    meta = R.SCENARIOS[scenario]
    pb = R.PLAYBOOKS.get(scenario) or R.PLAYBOOKS[R.PLAYBOOK_FOR.get(scenario, "server_compromise")]
    title = f"{meta['title']} response playbook"
    techs = [f for f in profile["facts"] if f["category"] == "tech"]
    related = [f for f in findings if scenario in (kb.THREATS.get(f.get("threat") or "", {}).get("scenarios") or [])][:4]
    L = [f"# {title}", "",
         f"**Profile:** {profile['name']}  ",
         f"**Drafted:** {date.today().isoformat()} by Threat Watch from its response guidance (NIST SP 800-61 Rev. 3 structure). This is a draft to review and adapt.",
         "", "> Containment, eradication and recovery steps require human judgement and the approvals your organisation defines. "
             "Threat Watch never runs them. Items marked **[to complete]** are organisation-specific and must not be guessed.", ""]
    if pb is not R.PLAYBOOKS.get(scenario):
        L += [f"_No dedicated template exists for this scenario yet; the {R.SCENARIOS[R.PLAYBOOK_FOR.get(scenario, 'server_compromise')]['title'].lower()} template is used as a starting point._", ""]
    L += ["## Why this playbook is relevant", ""]
    if related:
        for f in related:
            ev = f["evidence"][:2]
            L.append(f"- {f['priority']['code']} {f['title']} ({f['classification']})" + "".join(f" · [{e['source']}: {e['title']}]({e['url']})" for e in ev))
    else:
        L.append("- Common scenario for most organisations; no specific intelligence linked in the latest assessment.")
    L += ["", "## Roles and contacts", "", "- Incident lead: **[to complete]**", "- Deputy: **[to complete]**",
          "- Approves disruptive containment: **[to complete]**", "- Communications lead: **[to complete]**", "- Legal / privacy: **[to complete]**",
          "- External incident response provider: **[to complete]**", ""]
    L += ["## 1. Detection and initial triage", "", "**Triggers**", *[f"- {x}" for x in pb["triggers"]], "", "**Validate**",
          *[f"1. {x}" for x in pb["validate"]], "", "**Common false positives**", *[f"- {x}" for x in pb["false_positives"]], "",
          f"**Initial severity:** {pb['severity']}", "", "**Record:** affected identities and systems, their business criticality, time first seen, who reported it.", "",
          "**Preserve evidence first**", *[f"- {x}" for x in pb["preserve"]], ""]
    L += ["## 2. Investigation", "", "**Hypotheses to test**", *[f"- {x}" for x in pb["hypotheses"]], "", "**Log sources**",
          *[_tel_line(profile, k) for k in pb["telemetry"]], ""]
    if techs:
        L += ["**Technology listed for this profile:** " + ", ".join(f["value"] for f in techs[:12]), ""]
    L += ["**Possible attack progression (ATT&CK, for orientation, not a claim about this incident)**"]
    for tid in pb["progression"]:
        cur, _ = att.resolve(tid)
        L.append(f"- {cur} {att.tech.get(cur, {}).get('name') or ''}".rstrip())
    L += ["", "**Determine scope**", *[f"- {x}" for x in pb["scope"]], "- Build one timeline from the first to the last malicious event, with sources.", ""]
    L += ["## 3. Containment", "", "| Action | Business impact | Approval |", "|---|---|---|",
          *[f"| {a} | {i} | {w} **[confirm]** |" for a, i, w in pb["containment"]], "",
          "Preserve evidence before each action where feasible, and record the time of every action.", "",
          f"**Containment worked when:** {pb['containment_check']}", ""]
    L += ["## 4. Eradication", "", *[f"- {x}" for x in pb["eradicate"]], "- Confirm systems are clean before returning them to service.", ""]
    L += ["## 5. Recovery", "", *[f"- {x}" for x in pb["recover"]], "- Keep enhanced monitoring in place and agree when the incident is closed.", ""]
    L += ["## 6. Communication and escalation", "", *[f"- {x}" for x in pb["comms"]],
          "- Notification obligations (regulators, contracts, insurers): **[to complete after legal review]**", ""]
    L += ["## 7. Post-incident improvement", "", "- Root cause and contributing factors", *[f"- {x}" for x in pb["improve"]],
          "- Update this playbook, detections and training; track actions to completion.", ""]
    return title, "\n".join(L)


# ------------------------------------------------------------------ interview briefing
PROV = {"public": "Public, with sources (the fact that a source says it, not that the claim is true)", "user": "Entered by you", "inferred": "Inferred (assumption)", "unknown": "Unknown"}


def briefing_markdown(profile: dict, assessment: dict | None, findings: list[dict], prep: dict | None, answers: dict) -> str:
    L = [f"# {profile['name']}: cybersecurity briefing", ""]
    if prep:
        L += [f"**Role:** {prep['role']}  ", f"**Prepared:** {date.today().isoformat()}", ""]
    L += ["> Interview discussion aid built from public information, your notes and Threat Watch's collected intelligence. "
          "Threats listed are relevant to the sector and profile; they are **not** findings about the company's security.", ""]
    L += ["## The organisation", ""]
    if profile["description"]:
        L += [profile["description"], ""]
    for prov in ("public", "user", "inferred", "unknown"):
        facts = [f for f in profile["facts"] if f["provenance"] == prov and f["category"] not in ("telemetry", "control")]
        if not facts:
            continue
        L += [f"**{PROV[prov]}**", ""]
        for f in facts:
            src = f" ([{f['source_title'] or 'source'}]({f['source_url']}){', checked ' + f['verified_at'][:10] if f['verified_at'] else ''})" if f["source_url"] else ""
            L.append(f"- {f['category'].title()}: {f['value']}{src}{'; ' + f['note'] if f['note'] else ''}")
        L.append("")
    if assessment:
        L += [f"## Threat landscape (assessment {assessment['created_at'][:10]})", ""]
        for f in findings[:8]:
            L.append(f"### {f['priority']['code']} · {f['title']}")
            L.append(f"*{f['classification'].capitalize()}; evidence confidence: {f['confidence']['level']}.* {f['summary']}")
            for x in f["factors"]:
                L.append(f"- {x['factor']}: {x['detail']} ({x['basis']})")
            for e in f["evidence"][:3]:
                L.append(f"- Source: [{e['source']}: {e['title']}]({e['url']}) ({(e['published_at'] or '')[:10]})")
            techs = [t for t in f["techniques"] if set(t["basis"]) & {"reported", "group"}][:6] or f["techniques"][:4]
            if techs:
                L.append("- ATT&CK: " + ", ".join(f"{t['id']} {t.get('name') or ''}".strip() for t in techs))
            if f["unknowns"]:
                L.append("- Unknown: " + "; ".join(f["unknowns"]))
            L.append("")
    if prep:
        L += ["## Practice questions", ""]
        for k in R.interview_questions(prep["role"]):
            q = R.INTERVIEW[k]
            a = answers.get(k, {})
            L += [f"### {q['text']}", f"*{R.INTERVIEW_CATEGORIES[q['category']]}*", "", "Key points:", *[f"- {'[x]' if p in (a.get('covered') or []) else '[ ]'} {p}" for p in q["points"]],
                  "", "Pitfalls: " + "; ".join(q["pitfalls"]), ""]
            if a.get("answer"):
                L += ["My answer:", "", a["answer"], ""]
    return "\n".join(L)
