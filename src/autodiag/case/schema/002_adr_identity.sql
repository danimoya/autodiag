CREATE TABLE problems_v2 (
    target TEXT NOT NULL, node TEXT NOT NULL DEFAULT '',
    adr_home TEXT NOT NULL DEFAULT '', instance TEXT,
    problem_id INTEGER NOT NULL, problem_key TEXT NOT NULL,
    first_incident INTEGER, last_incident INTEGER, lastinc_time TEXT,
    first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
    PRIMARY KEY (target, node, adr_home, problem_id)
);
INSERT INTO problems_v2(target,adr_home,problem_id,problem_key,first_incident,
    last_incident,lastinc_time,first_seen_at,last_seen_at)
    SELECT target,adr_home,problem_id,problem_key,first_incident,
    last_incident,lastinc_time,first_seen_at,last_seen_at FROM problems;
DROP TABLE problems;
ALTER TABLE problems_v2 RENAME TO problems;
CREATE TABLE incidents_v2 (
    target TEXT NOT NULL, node TEXT NOT NULL DEFAULT '',
    adr_home TEXT NOT NULL DEFAULT '', instance TEXT,
    incident_id INTEGER NOT NULL, problem_id INTEGER, problem_key TEXT NOT NULL DEFAULT '',
    create_time TEXT, trace_file TEXT, seen_at TEXT NOT NULL,
    PRIMARY KEY (target, node, adr_home, incident_id)
);
INSERT INTO incidents_v2(target,incident_id,problem_id,problem_key,create_time,trace_file,seen_at)
    SELECT target,incident_id,problem_id,problem_key,create_time,trace_file,seen_at FROM incidents;
DROP TABLE incidents;
ALTER TABLE incidents_v2 RENAME TO incidents;
UPDATE schema_version SET version=2;
