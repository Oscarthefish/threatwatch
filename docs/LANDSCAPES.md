# Threat Landscapes

Profiles of an organisation or a sector, assessed against intelligence Threat Watch already collects, leading to
monitoring, hunting, hardening, incident readiness, response playbooks, exercises and interview preparation.
UI: **Defend → Threat landscapes** (`/landscapes`). API: `/api/landscapes` (authenticated, like every other route).

## Principles in the code

| Rule | Where |
|---|---|
| Every profile fact has a provenance: `user`, `public` (needs a source URL), `inferred` (assumption), `unknown` (open question). Nothing is promoted automatically. | `profile_facts`, `api/landscapes.py::_check_fact` |
| Nothing about a profile leaves the server: no AI calls, no web lookups, no scanning. Enrichment means matching the profile against collected reporting, KEV and leak-site claims. | `landscape/engine.py` |
| A threat is **observed** only with dated evidence tied to the organisation (sourced public facts, reporting that names it), its sector or countries, or a listed technology (KEV). Otherwise it is **emerging** (reporting rising, nothing tied to the profile), **historical** (only older evidence) or a **plausible scenario** (never claims an active campaign; capped at P3). | `engine.assess` |
| Priority = sum of listed factors, shown with points and basis. P1 ≥ 6, P2 ≥ 4, P3 ≥ 2. | `engine.priority_of` |
| CVSS never counts as exploitation; EPSS is labelled as FIRST's estimate; technology applies only when the analyst listed it; versions and exposure stay unknown. | `engine` KEV section |
| Unknown controls are reported as unknown. Only controls recorded as "implemented and tested" lower a priority, with the reason shown. | `engine` threat loop |
| Leak-site claims are always labelled as the groups' unverified statements. | `engine._claims`, UI |
| ATT&CK mappings carry a basis: named in reporting, documented by MITRE for a group in the evidence, keyword-inferred, or Threat Watch guidance (needs review). Revoked IDs resolve to their replacement. | `engine._finding`, `engine.Attack` |
| Readiness is scored only from the analyst's answers, and only once 60% of a scenario's questions are answered. | `landscape/response.py::readiness` |
| Playbooks never invent contacts, approvals or legal obligations (marked **[to complete]**) and Threat Watch never runs response actions. | `response.draft_playbook` |
| Example queries are labelled "Conceptual, not syntax-checked or tested". | `kb.MONITORING`, UI |

## Evidence rules (tuned against live data, 25 Nov 2026)
- Matching uses headline + feed summary only (body text produced false hits).
- Sector evidence: sector term in the headline (2 points) or only in the summary (1 point).
- Country evidence: the country in the headline, or a national agency of that country published it. Body mentions don't count.
- CISA vulnerability advisories count only when exploitation is reported. They list affected sectors and "denial-of-service condition", which are not threat activity.
- Court and policing follow-ups (arrests, extraditions, sentencing) are not current targeting.
- Negated clauses in facts ("no evidence of ransomware") are ignored.
- Roundups are excluded.
- Reconnaissance and Resource Development techniques are left out of the detection backlog.

## Data model (migration `007_landscapes.sql`)
- **ATT&CK:** `attack_tactics`, `attack_techniques`, `attack_mitigations`, `attack_detections` (detection strategies with analytics and log sources), `attack_links` (uses / mitigates / detects), `attack_revoked`. These are replaced on each weekly sync from `mitre-attack/attack-stix-data`, with the release recorded in the `attack_version` setting. Groups and software stay in `attack_objects`.
- **Profiles:** `profiles`, `profile_facts`.
- **Assessments:** `assessments` are immutable snapshots: inputs, findings and changes, plus a fingerprint. Unchanged results are not saved again. `finding_reviews` holds dismissals (a reason is required) and acceptances.
- **Work:** `coverage` per technique (telemetry and detection recorded separately), `landscape_actions`, `hunts`, `readiness_answers`, `playbooks` with `playbook_versions`, `exercises`, `interview_preps` with `interview_answers`.

Intelligence is not copied. Findings reference article IDs, CVE IDs and claim aggregates that already live elsewhere in the database.

## Knowledge base
`landscape/kb.py` holds the following. All of it is curated guidance, shown as guidance and never as intelligence:
- sectors (with ransomware.live sector names);
- telemetry (fields and event IDs);
- threat categories;
- monitoring items;
- hunts;
- hardening, with CIS Controls v8.1, NIST CSF 2.0 and ATT&CK mitigation references, each hand-checked.

`landscape/kb_response.py` holds the scenarios, readiness questions (NIST SP 800-61 Rev. 3 / CSF 2.0), playbook templates, the tabletop exercise and interview questions.

Tests check every cross-reference and that no technique ID revoked in ATT&CK v20 (T1562, T1070.001, T1656 …) is used.

## Sources and licensing
- **ATT&CK:** © The MITRE Corporation; free use with attribution. Fetched from GitHub through the SSRF-guarded fetcher.
- **CISA KEV:** public domain.
- **FIRST EPSS:** free; the FIRST attribution is shown.
- **ransomware.live:** free API, personal use; claims are unverified.
- **Navigator layer exports:** format 4.5 for ATT&CK Navigator.

## Case study: Fisher & Paykel Healthcare
Create it with `python -m app.cli case-study`. It is idempotent, and re-running it refreshes the facts.
- **Public facts:** each comes from the company's NZX/ASX statement of 22 Oct 2026 or Chris Lynch Media's report of 23 Nov 2026, checked 25 Nov 2026.
- **The Falcon claim:** the Falcon group's leak-site claim of 23 Nov 2026 is recorded as the group's unverified claim, with the company's response that it relates to the same incident.
- **Unknown:** the initial access method, the attacker, the email platform and the manufacturing locations. Do not fill these in without a source.
- **Seeded with it:** a mailbox-persistence practice hunt, an employee-account-compromise playbook draft and a Senior Cyber Security Analyst question set.

## Known limitations
- Collected history starts mid-September 2026, so trends and "historical" use a short baseline.
- Sector and threat matching is keyword-based. It can miss reports that never name the sector, and can match passing mentions in summaries (these score 1, not 2).
- Group techniques come from MITRE's documentation for groups named in the evidence. Relevant, but not proof of what happened in a given incident.
- No automatic web enrichment of profiles, by design. Public facts are entered with sources.
- ATT&CK for ICS and Mobile are not loaded; OT guidance uses Enterprise techniques.
- Example queries are conceptual; field names depend on the SIEM's parsing.
- Only one exercise scenario (employee account compromise) so far.
- Scheduled re-assessment is not built. Re-assess is manual, and the Overview shows when new reports have arrived since the last assessment.

## Progress and next steps
Done (local branch `feature/threat-landscapes`, not deployed):
- **M1, foundation:** navigation, profiles, provenance facts, dashboard.
- **M2, assessment:** engine, evidence, confidence, freshness.
- **M3, ATT&CK:** full v20.1 sync, matrix, technique detail, coverage, Navigator export.
- **M4, defence:** monitoring, hunts with a recorded outcome, hardening, telemetry gaps, actions.
- **M5, response:** readiness and improvement plan; versioned, exportable playbooks.
- **M6, interview prep:** questions, answers, reference points, Markdown briefing.
- **M7, change tracking:** snapshots, change summaries, history, dismissals.
- **M8, partial:** one tabletop exercise, coverage backlog.

Next, in order of value:
1. Deploy, after approval. The migration is additive; the first weekly ATT&CK sync after deploy loads techniques (or run ingest of `mitre-attack` once).
2. Scheduled re-assessment with a notification when a profile's priorities change (reuse `notify.send_push`).
3. More exercise scenarios (ransomware, BEC) and playbook templates for web intrusion, supply chain and OT.
4. Optional AI drafting for summaries or interview feedback. It needs a per-profile opt-in, because profile data must not leave the server by default.
5. Priority intelligence requirements (saved questions that steer the assessment).
