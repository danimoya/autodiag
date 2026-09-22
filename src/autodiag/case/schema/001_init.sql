-- AutoDiag case store (SQLite). Artifact files live next to it under cases/<case_id>/.
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS cases (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    problem_keys TEXT NOT NULL DEFAULT '[]',
    window_from  TEXT,
    window_to    TEXT,
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cases_target ON cases(target, status);

CREATE TABLE IF NOT EXISTS artifacts (
    id         TEXT PRIMARY KEY,
    case_id    TEXT NOT NULL REFERENCES cases(id),
    kind       TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    origin     TEXT NOT NULL DEFAULT '{}',
    label      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS artifacts_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS artifacts_sha ON artifacts(case_id, sha256);

CREATE TABLE IF NOT EXISTS evidence (
    id          TEXT PRIMARY KEY,
    case_id     TEXT REFERENCES cases(id),
    tool        TEXT NOT NULL,
    params      TEXT NOT NULL DEFAULT '{}',
    summary     TEXT NOT NULL DEFAULT '',
    artifact_id TEXT REFERENCES artifacts(id),
    line_from   INTEGER,
    line_to     INTEGER,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_case ON evidence(case_id);

CREATE TABLE IF NOT EXISTS findings (
    id         TEXT PRIMARY KEY,
    case_id    TEXT NOT NULL REFERENCES cases(id),
    kind       TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence   TEXT NOT NULL DEFAULT '[]',
    kb_refs    TEXT NOT NULL DEFAULT '[]',
    author     TEXT NOT NULL DEFAULT 'agent',
    status     TEXT NOT NULL DEFAULT 'proposed',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_case ON findings(case_id);

CREATE TABLE IF NOT EXISTS baselines (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    label       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS baselines_target ON baselines(target, kind);

CREATE TABLE IF NOT EXISTS reports (
    id              TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    kind            TEXT NOT NULL,
    markdown        TEXT NOT NULL,
    ips_artifact_id TEXT REFERENCES artifacts(id),
    rendered_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_case ON reports(case_id);

CREATE TABLE IF NOT EXISTS jobs (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'queued',
    params     TEXT NOT NULL DEFAULT '{}',
    result     TEXT NOT NULL DEFAULT '{}',
    error      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS problems (
    target         TEXT NOT NULL,
    problem_id     INTEGER NOT NULL,
    problem_key    TEXT NOT NULL,
    adr_home       TEXT NOT NULL DEFAULT '',
    first_incident INTEGER,
    last_incident  INTEGER,
    lastinc_time   TEXT,
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    PRIMARY KEY (target, problem_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    target      TEXT NOT NULL,
    incident_id INTEGER NOT NULL,
    problem_id  INTEGER,
    problem_key TEXT NOT NULL DEFAULT '',
    create_time TEXT,
    trace_file  TEXT,
    seen_at     TEXT NOT NULL,
    PRIMARY KEY (target, incident_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    new_problems TEXT NOT NULL DEFAULT '[]',
    summary      TEXT NOT NULL DEFAULT ''
);
