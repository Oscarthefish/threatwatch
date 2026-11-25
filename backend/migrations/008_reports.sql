-- Intelligence Reports Library (Phase 1): report series registry, reports with their documents,
-- extracted page text with page references, sections, and a processing history.
-- Documents are stored under <data_dir>/reports/<sha256>.pdf, never in the database or the repository.

CREATE TABLE report_sources (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,                 -- stable slug, e.g. "sentinelone-annual"
    publisher TEXT NOT NULL,
    series TEXT NOT NULL,
    page_url TEXT,                            -- official publication page, once verified
    frequency TEXT NOT NULL DEFAULT 'unknown',-- annual | quarterly | monthly | weekly | irregular | unknown
    category TEXT,                            -- frontline | landscape | specialist | government
    region TEXT NOT NULL DEFAULT 'GLOBAL',
    priority INTEGER NOT NULL DEFAULT 2,
    discovery_method TEXT NOT NULL DEFAULT 'manual', -- manual only in Phase 1; rss | page | sitemap later
    enabled INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT,                         -- when a person confirmed the page URL and frequency
    access_notes TEXT,                        -- registration wall, licence terms, etc.
    notes TEXT,
    seeded INTEGER NOT NULL DEFAULT 0,        -- 1 = from the built-in seed list
    last_checked_at TEXT,
    last_success_at TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY,
    source_id INTEGER REFERENCES report_sources(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    publisher TEXT,
    series TEXT,
    edition TEXT,                             -- e.g. "2026" or "Q3 2026"
    published_on TEXT,                        -- YYYY-MM-DD or YYYY-MM or YYYY
    period_start TEXT,
    period_end TEXT,
    publication_url TEXT,
    document_url TEXT,
    frequency TEXT,
    category TEXT,
    regions TEXT NOT NULL DEFAULT '[]',
    industries TEXT NOT NULL DEFAULT '[]',
    methodology TEXT,
    sample_size TEXT,                         -- free text: "1,200 IR engagements", not a bare number
    access_notes TEXT,                        -- copyright and redistribution restrictions
    notes TEXT,
    meta_source TEXT NOT NULL DEFAULT '{}',   -- field -> "user" | "pdf" | "filename"
    -- document
    sha256 TEXT UNIQUE,
    file_name TEXT,                           -- stored name inside data_dir/reports (sha256.pdf)
    original_filename TEXT,
    file_size INTEGER,
    retrieved_at TEXT,
    retrieval TEXT,                           -- upload | download
    page_count INTEGER,
    pdf_meta TEXT NOT NULL DEFAULT '{}',
    -- processing
    status TEXT NOT NULL DEFAULT 'discovered',-- discovered | queued | processing | processed | needs_review | failed
    status_detail TEXT,
    extraction_method TEXT,
    extraction_version INTEGER,
    extraction_confidence TEXT,               -- high | medium | low
    text_pages INTEGER,
    review_status TEXT NOT NULL DEFAULT 'unreviewed', -- unreviewed | reviewed
    bookmarked INTEGER NOT NULL DEFAULT 0,
    processed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_published ON reports(published_on);
CREATE INDEX idx_reports_source ON reports(source_id);

CREATE TABLE report_pages (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    page_no INTEGER NOT NULL,                 -- 1-based physical page
    label TEXT,                               -- printed page label when the PDF defines one
    text TEXT NOT NULL,
    chars INTEGER NOT NULL,
    UNIQUE(report_id, page_no)
);

CREATE VIRTUAL TABLE report_pages_fts USING fts5(text, content='report_pages', content_rowid='id', tokenize='porter unicode61');
CREATE TRIGGER report_pages_ai AFTER INSERT ON report_pages BEGIN
    INSERT INTO report_pages_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER report_pages_ad AFTER DELETE ON report_pages BEGIN
    INSERT INTO report_pages_fts(report_pages_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER report_pages_au AFTER UPDATE ON report_pages BEGIN
    INSERT INTO report_pages_fts(report_pages_fts, rowid, text) VALUES ('delete', old.id, old.text);
    INSERT INTO report_pages_fts(rowid, text) VALUES (new.id, new.text);
END;

CREATE TABLE report_sections (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    ord INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    title TEXT NOT NULL,
    page_start INTEGER,
    page_end INTEGER,
    origin TEXT NOT NULL                      -- outline (PDF bookmarks) | heading (detected)
);
CREATE INDEX idx_report_sections ON report_sections(report_id, ord);

CREATE TABLE report_jobs (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                       -- extract
    status TEXT NOT NULL,                     -- running | ok | needs_review | failed
    extractor TEXT,
    extractor_version INTEGER,
    pages INTEGER,
    text_pages INTEGER,
    chars INTEGER,
    sections INTEGER,
    detail TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX idx_report_jobs ON report_jobs(report_id, id);
