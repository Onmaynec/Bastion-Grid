"""Forward-only migrations; rollback is restore of a pre-upgrade SQLite backup."""
import json
import os
import sqlite3
from contextlib import closing
import uuid
from pathlib import Path

from .policy import DEFAULT_POLICY

CURRENT_SCHEMA = 2


def migrate(db):
    existing = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
    backup_path = None
    if existing:
        version = db.execute('SELECT MAX(version) FROM schema_version').fetchone()[0]
        if version is None or version > CURRENT_SCHEMA or version < 1:
            raise RuntimeError('Unsupported database schema; do not downgrade this database')
        if version == 1:
            source_path = db.execute('PRAGMA database_list').fetchone()[2]
            backup_path = source_path+'.pre-v2-'+uuid.uuid4().hex[:12]+'.sqlite3'
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
        db.commit()
    except BaseException:
        db.rollback()
        raise

    return backup_path
