-- Reports Phase 2: attributable findings with verified quotes, and AI extraction runs.

CREATE TABLE report_ai_runs (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    status TEXT NOT NULL,                    -- queued | running | done | stopped | failed | cancelled
    model TEXT,
    prompt_version INTEGER,
    chunks INTEGER NOT NULL DEFAULT 0,
    chunks_done INTEGER NOT NULL DEFAULT 0,
    estimate_usd REAL,
    cap_usd REAL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    proposed INTEGER NOT NULL DEFAULT 0,     -- findings the model returned
    kept INTEGER NOT NULL DEFAULT 0,         -- passed verification and were new
    rejected INTEGER NOT NULL DEFAULT 0,     -- failed verification (quote not on the page, bad values)
    detail TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX idx_report_ai_runs ON report_ai_runs(report_id, id);

CREATE TABLE report_findings (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    page_no INTEGER NOT NULL,
    quote TEXT NOT NULL,                     -- verbatim passage, verified present on the cited page
    quote_key TEXT NOT NULL,                 -- normalised quote, for de-duplication across re-runs
    title TEXT NOT NULL,
    summary TEXT,
    category TEXT NOT NULL,
    evidence_type TEXT NOT NULL,             -- what kind of evidence the report offers (see findings.EVIDENCE)
    techniques TEXT NOT NULL DEFAULT '[]',   -- [{id, name, basis: publisher | suggested}]
    cves TEXT NOT NULL DEFAULT '[]',
    actors TEXT NOT NULL DEFAULT '[]',
    technologies TEXT NOT NULL DEFAULT '[]',
    sectors TEXT NOT NULL DEFAULT '[]',
    regions TEXT NOT NULL DEFAULT '[]',
    statistic TEXT,                          -- {value, population, period, definition} exactly as stated
    confidence TEXT,                         -- high | medium | low: how clearly the passage supports the finding
    origin TEXT NOT NULL,                    -- analyst | summary | ai
    review_status TEXT NOT NULL DEFAULT 'unreviewed', -- unreviewed | accepted | rejected
    edited INTEGER NOT NULL DEFAULT 0,
    run_id INTEGER REFERENCES report_ai_runs(id) ON DELETE SET NULL,
    model TEXT,
    prompt_version INTEGER,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reviewed_at TEXT,
    UNIQUE(report_id, page_no, quote_key)
);
CREATE INDEX idx_report_findings ON report_findings(report_id, review_status);
