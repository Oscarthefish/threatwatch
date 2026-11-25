-- Threat Landscapes: ATT&CK techniques and relationships, organisation/industry profiles, assessments and the
-- defensive work that follows from them (coverage, hunts, actions, readiness, playbooks, interview preparation).

-- ---------------------------------------------------------------- MITRE ATT&CK (Enterprise), replaced on each sync
CREATE TABLE attack_tactics (
    attack_id  TEXT PRIMARY KEY,          -- TA0001
    shortname  TEXT NOT NULL UNIQUE,      -- initial-access
    name       TEXT NOT NULL,
    ord        INTEGER NOT NULL,          -- matrix column order
    url        TEXT NOT NULL
);
CREATE TABLE attack_techniques (
    attack_id   TEXT PRIMARY KEY,         -- T1566 or T1566.002
    stix_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    parent_id   TEXT,                     -- T1566 for T1566.002
    tactics     TEXT NOT NULL DEFAULT '[]',  -- tactic shortnames
    platforms   TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL,
    modified    TEXT
);
CREATE TABLE attack_mitigations (
    attack_id   TEXT PRIMARY KEY,         -- M1032
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL
);
CREATE TABLE attack_detections (
    attack_id  TEXT PRIMARY KEY,          -- DET0103 (detection strategy)
    name       TEXT NOT NULL,
    url        TEXT NOT NULL,
    analytics  TEXT NOT NULL DEFAULT '[]' -- [{id, platforms, description, log_sources:[{name, channel}]}]
);
-- Directed relationships between ATT&CK IDs: G0007 uses T1566, M1032 mitigates T1078, DET0103 detects T1070.
CREATE TABLE attack_links (
    src TEXT NOT NULL,
    rel TEXT NOT NULL,                    -- uses | mitigates | detects
    dst TEXT NOT NULL,
    PRIMARY KEY (src, rel, dst)
);
CREATE INDEX idx_attack_links_dst ON attack_links(dst, rel);
-- Old technique IDs that MITRE revoked, mapped to their replacement (so older reporting still resolves).
CREATE TABLE attack_revoked (
    old_id TEXT PRIMARY KEY,
    new_id TEXT NOT NULL
);

-- ---------------------------------------------------------------- profiles
CREATE TABLE profiles (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,           -- organisation | industry
    name         TEXT NOT NULL,
    sector       TEXT,                    -- one of the sector vocabulary keys (landscape.SECTORS)
    countries    TEXT NOT NULL DEFAULT '[]',  -- ISO 3166-1 alpha-2
    size         TEXT,                    -- small | medium | large | enterprise
    description  TEXT NOT NULL DEFAULT '',
    domain       TEXT,
    match_terms  TEXT NOT NULL DEFAULT '[]',  -- extra names used to find reporting about the organisation
    options      TEXT NOT NULL DEFAULT '{}',  -- assessment options: lookback_days, use_claims, excluded_sources
    notes        TEXT NOT NULL DEFAULT '',
    archived     INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
-- Everything else known about a profile. Provenance is explicit and never upgraded automatically:
--   user      entered by the analyst
--   public    publicly available, with a source URL (checked by the analyst on verified_at)
--   inferred  derived by a stated rule or by AI; shown as an assumption
--   unknown   recorded as an open question
CREATE TABLE profile_facts (
    id          INTEGER PRIMARY KEY,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    category    TEXT NOT NULL,            -- service | asset | supplier | regulation | tech | telemetry | control | context
    subtype     TEXT NOT NULL DEFAULT '', -- for tech: cloud, identity, email, endpoint, siem, internet_facing, software, ot, network
    value       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT '', -- telemetry: available|partial|not_available|unknown; control: implemented_tested|implemented|partial|not_implemented|unknown
    provenance  TEXT NOT NULL DEFAULT 'user',
    source_url  TEXT,
    source_title TEXT,
    verified_at TEXT,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX idx_profile_facts ON profile_facts(profile_id, category);

-- ---------------------------------------------------------------- assessments (immutable snapshots)
CREATE TABLE assessments (
    id             INTEGER PRIMARY KEY,
    profile_id     INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    created_at     TEXT NOT NULL,
    method_version INTEGER NOT NULL,
    attack_version TEXT,
    inputs         TEXT NOT NULL,         -- profile state, options and data freshness used
    findings       TEXT NOT NULL,         -- prioritised findings with reasons, evidence and techniques
    changes        TEXT NOT NULL DEFAULT '{}',  -- difference from the previous assessment
    fingerprint    TEXT NOT NULL          -- hash of inputs+evidence; unchanged inputs are not re-saved
);
CREATE INDEX idx_assessments_profile ON assessments(profile_id, created_at DESC);

-- Analyst decisions about a finding, kept across assessments (key = stable finding key).
CREATE TABLE finding_reviews (
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    decision    TEXT NOT NULL,            -- dismissed | accepted
    reason      TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (profile_id, finding_key)
);

-- Detection coverage per technique, as stated by the analyst. Telemetry, detection existence, testing and
-- effectiveness are separate on purpose: collecting a log is not proof that anything detects the technique.
CREATE TABLE coverage (
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    technique   TEXT NOT NULL,
    telemetry   TEXT NOT NULL DEFAULT 'unknown',  -- available | partial | not_available | unknown
    detection   TEXT NOT NULL DEFAULT 'unknown',  -- none | partial | implemented | validated | unknown
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (profile_id, technique)
);

-- Saved work items that came from a finding: detection, hunt, hardening, readiness, playbook update.
CREATE TABLE landscape_actions (
    id          INTEGER PRIMARY KEY,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,            -- detection | hardening | readiness | playbook
    ref         TEXT NOT NULL DEFAULT '', -- knowledge-base item or finding key it came from
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    priority    TEXT NOT NULL DEFAULT 'medium',
    owner       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',  -- open | in_progress | done | wont_do
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX idx_landscape_actions ON landscape_actions(profile_id, status);

CREATE TABLE hunts (
    id           INTEGER PRIMARY KEY,
    profile_id   INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    template     TEXT NOT NULL,           -- knowledge-base hunt key
    finding_key  TEXT,
    title        TEXT NOT NULL,
    plan         TEXT NOT NULL,           -- the plan as saved (editable copy of the template plus evidence)
    status       TEXT NOT NULL DEFAULT 'proposed',  -- proposed | ready | in_progress | completed | findings | blocked
    notes        TEXT NOT NULL DEFAULT '',
    conclusion   TEXT NOT NULL DEFAULT '',
    limitations  TEXT NOT NULL DEFAULT '',  -- what could not be checked (missing telemetry, retention)
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE readiness_answers (
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    question    TEXT NOT NULL,            -- knowledge-base question key (shared across scenarios)
    answer      TEXT NOT NULL,            -- tested | implemented | partial | not_implemented | unknown | na
    evidence    TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (profile_id, question)
);

CREATE TABLE playbooks (
    id          INTEGER PRIMARY KEY,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    scenario    TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,            -- Markdown, editable
    version     INTEGER NOT NULL DEFAULT 1,
    reviewed_at TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE playbook_versions (
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    body        TEXT NOT NULL,
    saved_at    TEXT NOT NULL,
    PRIMARY KEY (playbook_id, version)
);

CREATE TABLE interview_preps (
    id          INTEGER PRIMARY KEY,
    profile_id  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    job_description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE interview_answers (
    prep_id     INTEGER NOT NULL REFERENCES interview_preps(id) ON DELETE CASCADE,
    question    TEXT NOT NULL,            -- knowledge-base question key
    answer      TEXT NOT NULL DEFAULT '',
    covered     TEXT NOT NULL DEFAULT '[]',  -- reference points the analyst ticked as covered
    confidence  TEXT NOT NULL DEFAULT '',    -- '' | revise | ok | strong
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (prep_id, question)
);

-- Tabletop exercises and guided simulations (fictional scenarios; responses are the analyst's own).
CREATE TABLE exercises (
    id           INTEGER PRIMARY KEY,
    profile_id   INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    scenario     TEXT NOT NULL,
    format       TEXT NOT NULL DEFAULT 'individual',  -- individual | team | guided | open | interview
    difficulty   TEXT NOT NULL DEFAULT 'standard',    -- foundation | standard | advanced
    responses    TEXT NOT NULL DEFAULT '{}',          -- {question key: {answer, covered: [...]}}
    stage        INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    completed_at TEXT
);
