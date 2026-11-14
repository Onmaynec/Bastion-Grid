"""Durable local source bindings, admission budgets and dead-letter operations."""
import json
import sqlite3
import time

from .core import Problem, canonical, exact_fields, require, text_field, uid, utc

DEFAULT_QUOTAS = {'max_events_per_minute': 10000, 'max_bytes_per_day': 1073741824, 'max_pending': 10000}
QUOTA_LIMITS = {'max_events_per_minute': (1, 1000000), 'max_bytes_per_day': (1024, 107374182400),
                'max_pending': (1, 1000000)}


class Telemetry:
    def __init__(self, store):
        self.store = store

    def read_guard(self, p):
        self.store.authorize(p, 'audit')

    def write_guard(self, p):
        self.store.authorize(p, 'identity')

    def sources(self, p):
        self.read_guard(p)
        with self.store.connect() as db:
            rows = db.execute('SELECT * FROM sources WHERE tenant=? ORDER BY name LIMIT 501', (p['tenant'],)).fetchall()
            require(len(rows) <= 500, 'query_budget', 'Лимит списка источников — 500', 422)
            return {'items': [self.public_source(r) for r in rows]}

    @staticmethod
    def public_source(row):
        return {k: row[k] for k in ('id', 'source_id', 'name', 'collector_id', 'enabled', 'version', 'created_at',
                                     'last_seen', 'accepted_count', 'duplicate_count')} | {
            'asset_ids': json.loads(row['asset_ids'])}

    def create_source(self, p, body):
        self.write_guard(p)
        exact_fields(body, ['name', 'source_id', 'collector_id', 'asset_ids'],
                     ['name', 'source_id', 'collector_id', 'asset_ids'])
        name, source_id, collector_id = (text_field(body, k) for k in ('name', 'source_id', 'collector_id'))
        require(source_id == body['source_id'], message='source_id не должен содержать пробелы по краям')
        assets = body['asset_ids']
        require(isinstance(assets, list) and 1 <= len(assets) <= 100)
        require(all(isinstance(a, str) and 0 < len(a) <= 200 for a in assets))
        require(len(set(assets)) == len(assets))
        try:
            with self.store.tx() as db:
                self.store.live_principal(db, p)
                collector = db.execute("SELECT * FROM identities WHERE id=? AND tenant=? AND role='collector' "
                                       'AND revoked=0 AND expires>?', (collector_id, p['tenant'], time.time())).fetchone()
                require(collector is not None, 'not_found', 'Collector не найден или недействителен', 404)
                for asset_id in assets:
                    self.store.get(db, p, 'assets', asset_id)
                    # Registration may never enlarge the assigned collector's own ABAC policy.
                    self.store.get(db, dict(collector), 'assets', asset_id)
                object_id = uid()
                db.execute('INSERT INTO sources(id,tenant,source_id,name,collector_id,asset_ids,enabled,version,created_at) '
                           'VALUES(?,?,?,?,?,?,1,1,?)',
                           (object_id, p['tenant'], source_id, name, collector_id, canonical(sorted(assets)), utc()))
                self.store.audit(db, p, 'source.created', object_id,
                                 {'source_id': source_id, 'collector_id': collector_id, 'asset_ids': sorted(assets)})
                return self.public_source(db.execute('SELECT * FROM sources WHERE id=?', (object_id,)).fetchone())
        except sqlite3.IntegrityError:
            raise Problem(409, 'source_exists', 'source_id уже зарегистрирован в этом тенанте')

    def source_state(self, p, object_id, body, version):
        self.write_guard(p)
        exact_fields(body, ['enabled', 'reason'], ['enabled', 'reason'])
        require(type(body['enabled']) is bool)
        reason = text_field(body, 'reason', 1000)
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            row = db.execute('SELECT * FROM sources WHERE tenant=? AND id=?', (p['tenant'], object_id)).fetchone()
            require(row is not None, 'not_found', 'Источник не найден', 404)
            require(row['version'] == version, 'version_conflict', 'Версия источника изменилась', 409)
            db.execute('UPDATE sources SET enabled=?,version=version+1 WHERE id=?', (int(body['enabled']), object_id))
            self.store.audit(db, p, 'source.resumed' if body['enabled'] else 'source.paused', object_id,
                             {'reason': reason, 'version': version+1})
            return self.public_source(db.execute('SELECT * FROM sources WHERE id=?', (object_id,)).fetchone())

    def check_source(self, db, p, event):
        row = db.execute('SELECT * FROM sources WHERE tenant=? AND source_id=?',
                         (p['tenant'], event['source_id'])).fetchone()
        if row is None:
            require(p['role'] == 'admin', 'source_forbidden', 'Источник недоступен этому отправителю', 403)
            return  # Explicit local administrator injection, marked separately in the envelope.
        require(bool(row['enabled']) and row['collector_id'] == p.get('id')
                and event['asset_id'] in json.loads(row['asset_ids']),
                'source_forbidden', 'Источник недоступен этому отправителю', 403)

    def accepted_source(self, db, p, source_id, duplicate=False):
        column = 'duplicate_count' if duplicate else 'accepted_count'
        db.execute(f'UPDATE sources SET {column}={column}+1,last_seen=? WHERE tenant=? AND source_id=?',
                   (utc(), p['tenant'], source_id))

    def quotas_in(self, db, tenant):
        row = db.execute('SELECT * FROM telemetry_quotas WHERE tenant=?', (tenant,)).fetchone()
        return {k: row[k] for k in (*DEFAULT_QUOTAS, 'version')} if row else DEFAULT_QUOTAS | {'version': 1}

    def quotas(self, p):
        self.read_guard(p)
        with self.store.connect() as db:
            return self.quotas_in(db, p['tenant'])

    def set_quotas(self, p, body, version):
        self.write_guard(p)
        exact_fields(body, DEFAULT_QUOTAS.keys(), DEFAULT_QUOTAS.keys())
        for key, (low, high) in QUOTA_LIMITS.items():
            require(type(body[key]) is int and low <= body[key] <= high, message=f'{key}: {low}–{high}')
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            current = self.quotas_in(db, p['tenant'])
            require(current['version'] == version, 'version_conflict', 'Квоты уже изменены', 409)
            db.execute('INSERT INTO telemetry_quotas VALUES(?,?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET '
                       'max_events_per_minute=excluded.max_events_per_minute,max_bytes_per_day=excluded.max_bytes_per_day,'
                       'max_pending=excluded.max_pending,version=excluded.version',
                       (p['tenant'], body['max_events_per_minute'], body['max_bytes_per_day'], body['max_pending'], version+1))
            self.store.audit(db, p, 'telemetry.quotas_changed', p['tenant'], body | {'version': version+1})
            return body | {'version': version+1}

    def reserve(self, db, p, events_count, byte_count):
        if not events_count:
            return  # Retransmission of committed events must not consume another admission budget.
        quota = self.quotas_in(db, p['tenant'])
        now = int(time.time())
        minute, day = now//60*60, now//86400*86400
        usage = {}
        for period, bucket in [('minute', minute), ('day', day)]:
            row = db.execute('SELECT events,bytes FROM telemetry_usage WHERE tenant=? AND period=? AND bucket=?',
                             (p['tenant'], period, bucket)).fetchone()
            usage[period] = dict(row) if row else {'events': 0, 'bytes': 0}
        require(usage['minute']['events']+events_count <= quota['max_events_per_minute'],
                'rate_limited', 'Минутная квота событий исчерпана; повторите batch позже', 429)
        require(usage['day']['bytes']+byte_count <= quota['max_bytes_per_day'],
                'daily_quota', 'Суточная квота входных байтов исчерпана', 429)
        pending = db.execute("SELECT COUNT(*) FROM events WHERE tenant=? AND processed=0 AND work_state<>'dead'",
                             (p['tenant'],)).fetchone()[0]
        require(pending <= quota['max_pending'], 'backpressure', 'Очередь заполнена; batch не принят', 429)
        for period, bucket in [('minute', minute), ('day', day)]:
            db.execute('INSERT INTO telemetry_usage VALUES(?,?,?,?,?) ON CONFLICT(tenant,period,bucket) DO UPDATE '
                       'SET events=events+excluded.events,bytes=bytes+excluded.bytes',
                       (p['tenant'], period, bucket, events_count, byte_count))
        db.execute('DELETE FROM telemetry_usage WHERE tenant=? AND bucket<?', (p['tenant'], day-86400))

    def health(self, p):
        self.read_guard(p)
        with self.store.connect() as db:
            db.execute('BEGIN')
            counts = {r['work_state']: r['n'] for r in db.execute(
                'SELECT work_state,COUNT(*) AS n FROM events WHERE tenant=? GROUP BY work_state', (p['tenant'],))}
            oldest = db.execute("SELECT MIN(accepted_at) FROM events WHERE tenant=? AND processed=0 AND work_state<>'dead'",
                                (p['tenant'],)).fetchone()[0]
            worker = db.execute('SELECT * FROM worker_progress WHERE tenant=?', (p['tenant'],)).fetchone()
            return {'counts': {state: counts.get(state, 0) for state in ['pending', 'retry', 'dead', 'done']},
                    'stored_events': sum(counts.values()),
                    'oldest_pending_seconds': max(0, round(time.time()-oldest, 2)) if oldest is not None else None,
                    'worker': {k: worker[k] for k in ['last_attempt', 'last_success', 'last_error_code']} if worker else None,
                    'quotas': self.quotas_in(db, p['tenant']), 'profile': 'local-sqlite',
                    'automatic_attempts': 3, 'status': 'degraded' if counts.get('dead', 0) or counts.get('retry', 0) else 'backlog' if counts.get('pending', 0) else 'ok'}

    def dead_letters(self, p, after=0, limit=50):
        self.read_guard(p)
        require(type(after) is int and after >= 0 and type(limit) is int and 1 <= limit <= 100)
        with self.store.connect() as db:
            rows = db.execute("SELECT seq,source_id,event_id,attempts,error_code,work_revision,accepted_at "
                              "FROM events WHERE tenant=? AND work_state='dead' AND seq>? ORDER BY seq LIMIT ?",
                              (p['tenant'], after, limit+1)).fetchall()
        return {'items': [dict(row) for row in rows[:limit]],
                'next_cursor': rows[limit-1]['seq'] if len(rows) > limit else None}

    def retry_dead(self, p, seq, body, version):
        self.write_guard(p)
        exact_fields(body, ['reason'], ['reason'])
        reason = text_field(body, 'reason', 1000)
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            row = db.execute('SELECT * FROM events WHERE tenant=? AND seq=?', (p['tenant'], seq)).fetchone()
            require(row is not None, 'not_found', 'Событие не найдено', 404)
            require(row['work_revision'] == version, 'version_conflict', 'Состояние уже изменилось', 409)
            require(row['work_state'] == 'dead', 'invalid_state', 'Событие не находится в DLQ', 409)
            pending = db.execute("SELECT COUNT(*) FROM events WHERE tenant=? AND processed=0 AND work_state<>'dead'",
                                 (p['tenant'],)).fetchone()[0]
            require(pending < self.quotas_in(db, p['tenant'])['max_pending'], 'backpressure', 'Очередь заполнена', 429)
            db.execute("UPDATE events SET work_state='pending',attempts=0,next_attempt=0,error_code=NULL,"
                       'work_revision=work_revision+1 WHERE seq=?', (seq,))
            self.store.audit(db, p, 'telemetry.dead_letter_requeued', str(seq), {'reason': reason, 'version': version+1})
            return {'sequence': seq, 'state': 'pending', 'version': version+1}
