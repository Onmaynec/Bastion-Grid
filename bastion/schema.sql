CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES (1);
CREATE TABLE IF NOT EXISTS identities(
 token_hash TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL,
 role TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 UNIQUE(tenant,subject)
);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, identity_hash TEXT NOT NULL REFERENCES identities(token_hash),
 csrf TEXT NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS objects(
 tenant TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
 body TEXT NOT NULL, PRIMARY KEY(tenant,kind,id)
);
CREATE TABLE IF NOT EXISTS events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, source_id TEXT NOT NULL,
 event_id TEXT NOT NULL, event_time TEXT NOT NULL, body TEXT NOT NULL, digest TEXT NOT NULL,
 processed INTEGER NOT NULL DEFAULT 0, UNIQUE(tenant,source_id,event_id)
);
CREATE INDEX IF NOT EXISTS events_tenant_time ON events(tenant,event_time,seq);
CREATE INDEX IF NOT EXISTS events_pending ON events(processed,seq);
CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, body TEXT NOT NULL,
 prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant_seq ON audit(tenant,seq);
CREATE TABLE IF NOT EXISTS idempotency(
 tenant TEXT NOT NULL, subject TEXT NOT NULL, operation TEXT NOT NULL, key TEXT NOT NULL,
 digest TEXT NOT NULL, object_id TEXT NOT NULL,
 PRIMARY KEY(tenant,subject,operation,key)
);
CREATE TABLE IF NOT EXISTS detections(
 tenant TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL,
 event_seq INTEGER NOT NULL REFERENCES events(seq), alert_id TEXT NOT NULL,
 PRIMARY KEY(tenant,rule_id,rule_version,event_seq)
);
