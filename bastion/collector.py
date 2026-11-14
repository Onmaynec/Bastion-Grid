"""Visible foreground collector for the loopback lab; no remote execution or persistence."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from . import __version__
from .core import canonical, utc


class CollectorError(ValueError):
    pass


def config_file(path):
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    required = {'url', 'source_id', 'asset_id', 'token_file', 'spool'}
    if not isinstance(value, dict) or set(value) != required:
        raise CollectorError('Конфигурация: url, source_id, asset_id, token_file, spool')
    if any(not isinstance(v, str) or not v.strip() for v in value.values()):
        raise CollectorError('Поля конфигурации должны быть непустыми строками')
    parsed = urlsplit(value['url'])
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise CollectorError('Разрешён только http://127.0.0.1:port без пути и credentials')
    try:
        parsed.port
    except ValueError:
        raise CollectorError('Некорректный порт') from None
    value['url'] = value['url'].rstrip('/')
    for name in ('source_id', 'asset_id'):
        if value[name] != value[name].strip() or len(value[name]) > 200:
            raise CollectorError('Некорректный идентификатор источника или актива')
    for name in ('token_file', 'spool'):
        value[name] = str((Path(path).resolve().parent / value[name]).resolve())
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transport(config, event):
    # Read on every attempt: rotation replaces the token file, never event IDs or queue binding.
    token = Path(config['token_file']).read_text(encoding='utf-8').strip()
    if not token or len(token) > 4096 or any(c.isspace() for c in token):
        raise CollectorError('Некорректный файл ключа collector')
    request = Request(config['url']+'/api/v1/events/ingest',
                      data=canonical({'events': [event]}).encode(), method='POST',
                      headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+token})
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                return 502, {}, None
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError):
                return 502, {}, None
            return response.status, body, None
    except HTTPError as e:
        retry = e.headers.get('Retry-After', '')
        e.close()
        return e.code, {}, int(retry) if retry.isdigit() else None
    except (URLError, TimeoutError, OSError):
        return 503, {}, None


class Collector:
    def __init__(self, config, max_events=1000, max_bytes=4194304):
        if type(max_events) is not int or not 1 <= max_events <= 100000:
            raise CollectorError('max-events: 1–100000')
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 1073741824:
            raise CollectorError('max-bytes: 1024–1073741824')
        self.config, self.max_events, self.max_bytes = config, max_events, max_bytes
        self.path = Path(config['spool'])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        binding = hashlib.sha256(canonical({k: config[k] for k in ('url', 'source_id', 'asset_id')}).encode()).hexdigest()
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            old = db.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
            if old and old[0] != binding:
                raise CollectorError('Очередь принадлежит другому endpoint/source/asset; используйте другой spool')
            schema = db.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
            if schema and schema[0] != '1':
                raise CollectorError('Неизвестная версия очереди')
            db.execute("INSERT OR IGNORE INTO metadata VALUES('binding',?)", (binding,))
            db.execute("INSERT OR IGNORE INTO metadata VALUES('schema','1')")
            db.execute('CREATE TABLE IF NOT EXISTS queue(seq INTEGER PRIMARY KEY AUTOINCREMENT, '
                       'body TEXT NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, '
                       'next_attempt REAL NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, code INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL)')
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def count(db, name):
        db.execute('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1', (name,))

    def sample(self):
        # Deliberately excludes usernames, process arguments, files, addresses and machine identifiers.
        event = {'event_id': str(uuid.uuid4()), 'source_id': self.config['source_id'],
                 'asset_id': self.config['asset_id'], 'event_time': utc(), 'schema_version': 1,
                 'attributes': {'event_type': 'endpoint_heartbeat', 'collector_version': __version__,
                                'os_family': platform.system(), 'os_release': platform.release()[:200],
                                'architecture': platform.machine()[:200], 'python_version': platform.python_version(),
                                'profile': 'local-lab'}}
        body = canonical(event)
        size = len(body.encode('utf-8'))
        with self.db() as db:
            usage = db.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM queue').fetchone()
            if usage[0] >= self.max_events or usage[1]+size > self.max_bytes:
                self.count(db, 'dropped')
                return False
            db.execute('INSERT INTO queue(body,size) VALUES(?,?)', (body, size))
            self.count(db, 'sampled')
        return True

    def status(self):
        with self.db() as db:
            row = db.execute('SELECT COUNT(*) AS queued,COALESCE(SUM(size),0) AS payload_bytes, '
                             'COALESCE(SUM(blocked),0) AS blocked,MIN(next_attempt) AS next_attempt FROM queue').fetchone()
            head = db.execute('SELECT attempts,code,blocked FROM queue ORDER BY seq LIMIT 1').fetchone()
            return dict(row) | {'head': dict(head) if head else None, 'counters': {r['name']: r['value'] for r in db.execute('SELECT * FROM counters')},
                                'max_events': self.max_events, 'max_bytes': self.max_bytes,
                                'profile': 'local-lab', 'encrypted': False}

    def retry_blocked(self):
        with self.db() as db:
            n = db.execute('UPDATE queue SET blocked=0,next_attempt=0 WHERE blocked=1').rowcount
            if n:
                self.count(db, 'manual_retries')
            return n

    def flush(self, limit=100, send=transport):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise CollectorError('limit: 1–1000')
        delivered = 0
        for _ in range(limit):
            # One local writer owns the send/ack decision, including concurrent CLI instances.
            # Network timeout is bounded; a crash after remote commit keeps the original event ID.
            with self.db() as db:
                row = db.execute('SELECT * FROM queue ORDER BY seq LIMIT 1').fetchone()
                if not row or row['blocked'] or row['next_attempt'] > time.time():
                    break
                status, body, retry = send(self.config, json.loads(row['body']))
                accepted, duplicates = (body.get('accepted'), body.get('duplicates')) if isinstance(body, dict) else (None, None)
                valid_ack = (status == 200 and isinstance(body, dict) and body.get('durable') is True
                             and isinstance(accepted, list) and isinstance(duplicates, list)
                             and len(accepted)+len(duplicates) == 1
                             and all(type(n) is int and n > 0 for n in accepted+duplicates))
                if valid_ack:
                    db.execute('DELETE FROM queue WHERE seq=?', (row['seq'],))
                    self.count(db, 'duplicates' if duplicates else 'accepted')
                    delivered += 1
                    continue
                permanent = 300 <= status < 500 and status not in (408, 429)
                delay = min(300, 2**min(row['attempts'], 8))
                if status == 429 and type(retry) is int:
                    delay = max(delay, min(86400, max(1, retry)))
                db.execute('UPDATE queue SET attempts=attempts+1,next_attempt=?,blocked=?,code=? WHERE seq=?',
                           (time.time()+delay, int(permanent), status, row['seq']))
                self.count(db, 'blocked_attempts' if permanent else 'retry_attempts')
                break
        return delivered


def main():
    parser = argparse.ArgumentParser(description='BASTION GRID: явный локальный collector, без установки службы')
    parser.add_argument('--config', required=True)
    parser.add_argument('--max-events', type=int, default=1000)
    parser.add_argument('--max-bytes', type=int, default=4194304)
    parser.add_argument('command', choices=['sample', 'flush', 'status', 'run', 'retry-blocked'])
    parser.add_argument('--interval', type=int, default=60)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if not 5 <= args.interval <= 3600:
            raise CollectorError('interval: 5–3600 секунд')
        collector = Collector(config_file(args.config), args.max_events, args.max_bytes)
        if args.command == 'run':
            print('Collector local-lab запущен; Ctrl+C останавливает процесс. Очередь НЕ зашифрована.', flush=True)
            while True:
                collector.sample()
                collector.flush()
                print(json.dumps(collector.status(), ensure_ascii=False), flush=True)
                time.sleep(args.interval)
        elif args.command == 'sample':
            if not collector.sample():
                print('Очередь заполнена; новое наблюдение не сохранено.')
                return 2
        elif args.command == 'flush':
            collector.flush()
        elif args.command == 'retry-blocked':
            collector.retry_blocked()
        print(json.dumps(collector.status(), ensure_ascii=False, indent=2))
        return 0
    except KeyboardInterrupt:
        print('Collector остановлен; очередь сохранена.')
        return 0
    except (CollectorError, OSError, sqlite3.Error, ValueError):
        # Do not print token file contents, network response bodies or sensitive filesystem paths.
        print('Ошибка collector: проверьте конфигурацию, файл ключа и доступ к очереди.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
