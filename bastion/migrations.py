"""Forward-only migrations; rollback is restore of a pre-upgrade SQLite backup."""
import json
import os
import sqlite3
from contextlib import closing
import uuid
from pathlib import Path

from .policy import DEFAULT_POLICY

CURRENT_SCHEMA = 3


def migrate(db):
    existing = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
    backup_path = None
    if existing:
        version = db.execute('SELECT MAX(version) FROM schema_version').fetchone()[0]
        if version is None or version > CURRENT_SCHEMA or version < 1:
            raise RuntimeError('Unsupported database schema; do not downgrade this database')
        if version < CURRENT_SCHEMA:
            source_path = db.execute('PRAGMA database_list').fetchone()[2]
            backup_path = source_path+f'.pre-v{CURRENT_SCHEMA}-'+uuid.uuid4().hex[:12]+'.sqlite3'
            fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            try:
                with closing(sqlite3.connect(backup_path)) as target:
                    db.backup(target)
            except BaseException:
                Path(backup_path).unlink(missing_ok=True)
                raise
    schema = Path(__file__).with_name('schema.sql').read_text(encoding='utf-8')
    db.executescript('BEGIN IMMEDIATE;\n'+schema+'\nCOMMIT;')
    db.execute('BEGIN IMMEDIATE')
    try:
        version = db.execute('SELECT MAX(version) FROM schema_version').fetchone()[0]
        if version == 1:
            db.execute('ALTER TABLE identities ADD COLUMN id TEXT')
            db.execute('ALTER TABLE identities ADD COLUMN version INTEGER NOT NULL DEFAULT 1')
            db.execute('ALTER TABLE identities ADD COLUMN policy TEXT')
            for row in db.execute('SELECT token_hash FROM identities').fetchall():
                db.execute('UPDATE identities SET id=?,policy=? WHERE token_hash=?',
                           (str(uuid.uuid4()), json.dumps(DEFAULT_POLICY, sort_keys=True), row[0]))
            db.execute('CREATE UNIQUE INDEX identities_id ON identities(id)')
            # Old sessions are intentionally closed at the authentication boundary.
            db.execute('DELETE FROM sessions')
            db.execute('ALTER TABLE sessions ADD COLUMN id TEXT')
            db.execute('ALTER TABLE sessions ADD COLUMN created_at REAL NOT NULL DEFAULT 0')
            db.execute('ALTER TABLE sessions ADD COLUMN last_seen REAL NOT NULL DEFAULT 0')
            db.execute('CREATE UNIQUE INDEX sessions_id ON sessions(id)')
            db.execute('INSERT INTO schema_version VALUES(2)')
            version = 2
        if version == 2:
            statements = [
                "ALTER TABLE events ADD COLUMN work_state TEXT NOT NULL DEFAULT 'pending'",
                "ALTER TABLE events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE events ADD COLUMN next_attempt REAL NOT NULL DEFAULT 0",
                "ALTER TABLE events ADD COLUMN error_code TEXT",
                "ALTER TABLE events ADD COLUMN work_revision INTEGER NOT NULL DEFAULT 1",
                "ALTER TABLE events ADD COLUMN accepted_at REAL NOT NULL DEFAULT 0",
                "UPDATE events SET work_state=CASE WHEN processed=1 THEN 'done' ELSE 'pending' END, "
                "accepted_at=COALESCE(CAST(strftime('%s',json_extract(body,'$.ingest_time')) AS REAL),0)",
                "CREATE INDEX events_work ON events(processed,work_state,next_attempt,seq)",
                "CREATE TABLE sources(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,source_id TEXT NOT NULL,"
                "name TEXT NOT NULL,collector_id TEXT NOT NULL,asset_ids TEXT NOT NULL,enabled INTEGER NOT NULL,"
                "version INTEGER NOT NULL,created_at TEXT NOT NULL,last_seen TEXT,accepted_count INTEGER NOT NULL DEFAULT 0,"
                "duplicate_count INTEGER NOT NULL DEFAULT 0,UNIQUE(tenant,source_id))",
                "CREATE TABLE telemetry_quotas(tenant TEXT PRIMARY KEY,max_events_per_minute INTEGER NOT NULL,"
                "max_bytes_per_day INTEGER NOT NULL,max_pending INTEGER NOT NULL,version INTEGER NOT NULL)",
                "CREATE TABLE telemetry_usage(tenant TEXT NOT NULL,period TEXT NOT NULL,bucket INTEGER NOT NULL,"
                "events INTEGER NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(tenant,period,bucket))",
                "CREATE TABLE worker_progress(tenant TEXT PRIMARY KEY,last_attempt REAL NOT NULL,last_success REAL,"
                "last_error_code TEXT)",
                "INSERT INTO schema_version VALUES(3)",
            ]
            for statement in statements:
                db.execute(statement)
        db.commit()
    except BaseException:
        db.rollback()
        raise

    return backup_path
