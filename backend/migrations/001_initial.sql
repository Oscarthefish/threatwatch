-- Threat Watch initial schema.
-- Evidence (sources/articles/vulnerabilities) is kept separate from
-- model-generated output (ai_outputs, briefings, watch_summaries).

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,           -- sha256 of the cookie token; raw token never stored
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    user_agent  TEXT
);

CREATE TABLE login_attempts (
    id         INTEGER PRIMARY KEY,
    client     TEXT NOT NULL,
    at         TEXT NOT NULL,
    success    INTEGER NOT NULL
);
CREATE INDEX idx_login_attempts ON login_attempts(client, at);

CREATE TABLE sources (
    id               INTEGER PRIMARY KEY,
    key              TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,          -- rss | kev | epss | ncsc_nz_html
    url              TEXT NOT NULL,
    homepage         TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    interval_minutes INTEGER NOT NULL DEFAULT 30,
    authority        INTEGER NOT NULL DEFAULT 2,   -- 3 official/government, 2 established research/press, 1 other
    region           TEXT,                   -- NZ | AU | APAC | GLOBAL
    default_sections TEXT NOT NULL DEFAULT '[]',
    etag             TEXT,
    last_modified    TEXT,
    last_fetched_at  TEXT,
    last_success_at  TEXT,
    last_status      TEXT,
    last_error       TEXT,
    items_last_run   INTEGER DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE articles (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES sources(id),
    url             TEXT NOT NULL,           -- original URL as published
    canonical_url   TEXT NOT NULL UNIQUE,    -- normalised for exact dedupe
    guid            TEXT,
    title           TEXT NOT NULL,
    author          TEXT,
    summary_text    TEXT NOT NULL DEFAULT '',-- sanitised plain text from the feed (untrusted)
    content_text    TEXT NOT NULL DEFAULT '',-- sanitised plain text body if the feed provides it (untrusted)
    published_at    TEXT,                    -- source-stated publication time (UTC ISO)
    retrieved_at    TEXT NOT NULL,           -- when we fetched it
    title_tokens    TEXT NOT NULL DEFAULT '',-- normalised token set for near-dup detection
    cluster_id      INTEGER,                 -- id of the first article in a near-duplicate cluster
    sections        TEXT NOT NULL DEFAULT '[]',
    tags            TEXT NOT NULL DEFAULT '[]',   -- machine classification labels
    severity        INTEGER NOT NULL DEFAULT 1,   -- 0 info .. 4 critical
    severity_reasons TEXT NOT NULL DEFAULT '[]',
    confidence      TEXT NOT NULL DEFAULT 'single-source',
    score           REAL NOT NULL DEFAULT 0,      -- ranking score
    region          TEXT,
    extracted_at    TEXT,
    matched_at      TEXT                     -- when watch matching last ran on this article
);
CREATE INDEX idx_articles_published ON articles(published_at DESC);
CREATE INDEX idx_articles_retrieved ON articles(retrieved_at DESC);
CREATE INDEX idx_articles_cluster ON articles(cluster_id);
CREATE INDEX idx_articles_source ON articles(source_id);

CREATE VIRTUAL TABLE articles_fts USING fts5(
    title, summary_text, content_text,
    content='articles', content_rowid='id',
    tokenize = 'porter unicode61'
);
CREATE TRIGGER articles_ai AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, summary_text, content_text)
    VALUES (new.id, new.title, new.summary_text, new.content_text);
END;
CREATE TRIGGER articles_ad AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, summary_text, content_text)
    VALUES ('delete', old.id, old.title, old.summary_text, old.content_text);
END;
CREATE TRIGGER articles_au AFTER UPDATE OF title, summary_text, content_text ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, summary_text, content_text)
    VALUES ('delete', old.id, old.title, old.summary_text, old.content_text);
    INSERT INTO articles_fts(rowid, title, summary_text, content_text)
    VALUES (new.id, new.title, new.summary_text, new.content_text);
END;

CREATE TABLE entities (
    id         INTEGER PRIMARY KEY,
    type       TEXT NOT NULL,     -- cve | attack_technique | actor | malware | ransomware | vendor | product | ipv4 | domain | sha256 | sha1 | md5 | url | country
    value      TEXT NOT NULL,     -- display form
    normalized TEXT NOT NULL,
    UNIQUE(type, normalized)
);

CREATE TABLE article_entities (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    entity_id  INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    in_title   INTEGER NOT NULL DEFAULT 0,
    method     TEXT NOT NULL DEFAULT 'rule', -- rule | ai
    PRIMARY KEY (article_id, entity_id)
);
CREATE INDEX idx_article_entities_entity ON article_entities(entity_id);

CREATE TABLE vulnerabilities (
    cve_id            TEXT PRIMARY KEY,
    vendor            TEXT,
    product           TEXT,
    name              TEXT,
    description       TEXT,
    cvss_score        REAL,
    cvss_severity     TEXT,
    cvss_vector       TEXT,
    cvss_source       TEXT,
    kev               INTEGER NOT NULL DEFAULT 0,
    kev_date_added    TEXT,
    kev_due_date      TEXT,
    kev_ransomware    TEXT,
    kev_required_action TEXT,
    kev_notes         TEXT,
    kev_cwes          TEXT,
    epss              REAL,
    epss_percentile   REAL,
    epss_date         TEXT,
    references_json   TEXT NOT NULL DEFAULT '[]',
    first_seen_at     TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    enriched_at       TEXT
);
CREATE INDEX idx_vuln_kev_added ON vulnerabilities(kev_date_added DESC);
CREATE INDEX idx_vuln_epss ON vulnerabilities(epss DESC);

-- Model-generated output, cached by input hash. Never treated as evidence.
CREATE TABLE ai_outputs (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,       -- article_summary | entity_extraction | briefing | watch_match | watch_update
    subject_type TEXT,
    subject_id   INTEGER,
    input_hash   TEXT NOT NULL,
    model        TEXT NOT NULL,
    output_json  TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd     REAL NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    UNIQUE(kind, input_hash)
);
CREATE INDEX idx_ai_subject ON ai_outputs(subject_type, subject_id, kind);

CREATE TABLE ai_usage (
    day          TEXT PRIMARY KEY,    -- YYYY-MM-DD (UTC)
    requests     INTEGER NOT NULL DEFAULT 0,
    failures     INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd     REAL NOT NULL DEFAULT 0
);

CREATE TABLE briefings (
    id           INTEGER PRIMARY KEY,
    briefing_date TEXT NOT NULL,      -- local date (Pacific/Auckland)
    generated_at TEXT NOT NULL,
    method       TEXT NOT NULL,       -- ai | heuristic
    model        TEXT,
    content_json TEXT NOT NULL,       -- {headline, items:[{title, summary, why, article_ids, severity}]}
    article_ids  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_briefings_date ON briefings(briefing_date DESC, generated_at DESC);

CREATE TABLE bookmarks (
    article_id  INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE reading_history (
    article_id INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    first_read_at TEXT NOT NULL,
    last_read_at  TEXT NOT NULL,
    read_count    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE watches (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL,     -- incident | vulnerability | actor | malware | campaign | product | topic
    title           TEXT NOT NULL,
    canonical_key   TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    identifiers     TEXT NOT NULL DEFAULT '[]', -- strong identifiers, e.g. CVE ids, victim org names
    aliases         TEXT NOT NULL DEFAULT '[]', -- alternate names (APT29, Midnight Blizzard, ...)
    context_terms   TEXT NOT NULL DEFAULT '[]', -- supporting terms (actor, malware, sector) that boost but never suffice alone for incidents
    exclude_terms   TEXT NOT NULL DEFAULT '[]',
    notify_pref     TEXT NOT NULL DEFAULT 'important', -- important | all | digest | silent
    status          TEXT NOT NULL DEFAULT 'active',    -- active | archived
    tags            TEXT NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT '',
    origin_article_id INTEGER REFERENCES articles(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    last_checked_at TEXT,
    last_updated_at TEXT,
    last_viewed_at  TEXT
);

CREATE TABLE watch_evidence (
    id            INTEGER PRIMARY KEY,
    watch_id      INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
    article_id    INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'linked',  -- linked | candidate | rejected
    match_score   REAL NOT NULL,
    match_reasons TEXT NOT NULL DEFAULT '[]',
    significance  TEXT NOT NULL DEFAULT 'unassessed', -- important | meaningful | duplicate | minor | unassessed
    assessment    TEXT NOT NULL DEFAULT '',  -- why it does / doesn't add information
    linked_by     TEXT NOT NULL DEFAULT 'auto', -- auto | user | origin
    linked_at     TEXT NOT NULL,
    processed_at  TEXT,                       -- folded into a summary version
    UNIQUE(watch_id, article_id)
);
CREATE INDEX idx_watch_evidence_watch ON watch_evidence(watch_id, status);

CREATE TABLE watch_summaries (
    id            INTEGER PRIMARY KEY,
    watch_id      INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    method        TEXT NOT NULL,       -- ai | heuristic
    model         TEXT,
    summary       TEXT NOT NULL,       -- cumulative summary; claims cite evidence as [E<article_id>]
    confirmed     TEXT NOT NULL DEFAULT '[]',   -- [{claim, article_ids}]
    uncertain     TEXT NOT NULL DEFAULT '[]',   -- [{claim, article_ids, note}]
    changes       TEXT NOT NULL DEFAULT '[]',   -- [{change, article_ids}] what changed vs previous version
    iocs          TEXT NOT NULL DEFAULT '[]',   -- [{type, value, article_ids}]
    techniques    TEXT NOT NULL DEFAULT '[]',   -- [{id, name, article_ids}]
    detection     TEXT NOT NULL DEFAULT '[]',   -- [{guidance, article_ids}]
    evidence_ids  TEXT NOT NULL DEFAULT '[]',   -- articles considered for this version
    UNIQUE(watch_id, version)
);

CREATE TABLE watch_timeline (
    id          INTEGER PRIMARY KEY,
    watch_id    INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    event_type  TEXT NOT NULL,   -- created | evidence | summary | note | status | user_link | user_reject
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    article_id  INTEGER REFERENCES articles(id) ON DELETE SET NULL,
    summary_version INTEGER
);
CREATE INDEX idx_watch_timeline ON watch_timeline(watch_id, occurred_at DESC);

CREATE TABLE notifications (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL,
    kind        TEXT NOT NULL,    -- watch_important | watch_update | digest | briefing | system
    title       TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',
    link        TEXT,
    watch_id    INTEGER REFERENCES watches(id) ON DELETE CASCADE,
    article_id  INTEGER REFERENCES articles(id) ON DELETE SET NULL,
    dedupe_key  TEXT NOT NULL UNIQUE,
    read_at     TEXT,
    pushed_at   TEXT,
    digest_pending INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);

CREATE TABLE push_subscriptions (
    endpoint    TEXT PRIMARY KEY,
    p256dh      TEXT NOT NULL,
    auth        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    user_agent  TEXT
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE job_runs (
    id          INTEGER PRIMARY KEY,
    job         TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_job_runs ON job_runs(job, started_at DESC);
