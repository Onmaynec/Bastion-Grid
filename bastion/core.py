"""Transactional local baseline. No remote execution and no production identity claims."""
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .migrations import migrate
from .policy import DEFAULT_POLICY, SENSITIVITY, asset_allowed, policy_of, unrestricted

ROLES = {
    'admin': {'read', 'asset', 'ingest', 'rule', 'publish', 'case', 'request', 'approve', 'audit', 'identity'},
    'analyst': {'read', 'case', 'request'},
    'lead': {'read', 'case', 'request', 'approve', 'publish', 'audit'},
    'auditor': {'read', 'audit'},
    'collector': {'ingest'},
}
STATES = {
    'NEW': {'TRIAGE', 'CLOSED'}, 'TRIAGE': {'INVESTIGATING', 'CLOSED'},
    'INVESTIGATING': {'CONTAINED', 'RECOVERING', 'RESOLVED'},
    'CONTAINED': {'RECOVERING', 'INVESTIGATING'},
    'RECOVERING': {'RESOLVED', 'INVESTIGATING'},
    'RESOLVED': {'CLOSED', 'INVESTIGATING'}, 'CLOSED': {'INVESTIGATING'},
}
ACTIONS = {'collect_metadata', 'isolate_host', 'release_isolation'}
ZERO = '0' * 64


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def uid():
    return str(uuid.uuid4())


class Problem(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


def require(condition, code='validation_error', message='Некорректные данные', status=400):
    if not condition:
        raise Problem(status, code, message)


def text_field(body, key, maximum=200):
    value = body.get(key)
    require(isinstance(value, str) and 0 < len(value.strip()) <= maximum,
            message=f'Поле {key}: требуется строка длиной 1–{maximum}')
    return value.strip()


def exact_fields(body, allowed, required=()):
    require(isinstance(body, dict), message='Ожидается JSON object')
    require(set(body) <= set(allowed), message='Неизвестные поля')
    require(set(required) <= set(body), message='Отсутствуют обязательные поля')


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            self.migration_backup = migrate(db)
        from .access import AccessControl
        self.access = AccessControl(self)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        return db

    @contextmanager
    def connect(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def tx(self):
        db = self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def identity(self, tenant, subject, role, lifetime=86400):
        require(role in ROLES)
        token = secrets.token_urlsafe(32)
        with self.tx() as db:
            db.execute('INSERT INTO identities(token_hash,tenant,subject,role,expires,revoked,id,version,policy) '
                       'VALUES(?,?,?,?,?,0,?,1,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), tenant, subject, role, time.time()+lifetime,
                        uid(), canonical(DEFAULT_POLICY)))
        return token

    def authenticate(self, token):
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as db:
            row = db.execute('SELECT * FROM identities WHERE token_hash=? AND revoked=0 AND expires>?',
                             (key, time.time())).fetchone()
        require(row is not None, 'unauthorized', 'Требуется действующая учётная запись', 401)
        return dict(row)

    def live_principal(self, db, p):
        if 'token_hash' not in p:
            return  # Trusted in-process worker/CLI context; never accepted from HTTP input.
        row = db.execute('SELECT * FROM identities WHERE token_hash=? AND tenant=? AND revoked=0 AND expires>?',
                         (p['token_hash'], p['tenant'], time.time())).fetchone()
        require(row is not None and row['version'] == p.get('version') and row['role'] == p['role']
                and row['policy'] == p.get('policy'), 'unauthorized', 'Учётная запись изменилась; повторите вход', 401)
        if p.get('session_id'):
            session = db.execute('SELECT 1 FROM sessions WHERE id=? AND identity_hash=? AND expires>?',
                                 (p['session_id'], p['token_hash'], time.time())).fetchone()
            require(session is not None, 'unauthorized', 'Сеанс завершён', 401)

    def authorize(self, p, permission):
        if (permission not in ROLES[p['role']] or
                (permission in {'audit', 'rule', 'publish', 'identity'} and not unrestricted(p))):
            with self.tx() as db:
                self.audit(db, p, 'access.denied', permission, {'decision': 'deny', 'policy_version': 1})
            raise Problem(403, 'forbidden', 'Недостаточно полномочий')

    def audit(self, db, p, action, resource, details=None):
        row = db.execute('SELECT hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1',
                         (p['tenant'],)).fetchone()
        previous = row['hash'] if row else ZERO
        body = {'id': uid(), 'tenant_id': p['tenant'], 'actor': p['subject'], 'time': utc(),
                'action': action, 'resource': resource, 'details': details or {}}
        hash_value = hashlib.sha256((previous + canonical(body)).encode()).hexdigest()
        db.execute('INSERT INTO audit(tenant,body,prev_hash,hash) VALUES(?,?,?,?)',
                   (p['tenant'], canonical(body), previous, hash_value))

    def raw_object(self, db, tenant, kind, object_id):
        row = db.execute('SELECT body FROM objects WHERE tenant=? AND kind=? AND id=?',
                         (tenant, kind, object_id)).fetchone()
        return json.loads(row['body']) if row else None

    def visible(self, db, p, kind, obj):
        if obj is None:
            return False
        if kind == 'assets':
            return asset_allowed(p, obj)
        if kind == 'rules':
            return unrestricted(p)
        if kind in {'events', 'alerts'}:
            asset = self.raw_object(db, p['tenant'], 'assets', obj.get('asset_id'))
            return asset is not None and asset_allowed(p, asset)
        if kind == 'cases':
            alert = self.raw_object(db, p['tenant'], 'alerts', obj.get('alert_id'))
            return (self.visible(db, p, 'alerts', alert) and
                    (not policy_of(p)['assigned_only'] or obj.get('owner') == p['subject']))
        if kind in {'responses', 'evidence'}:
            case = self.raw_object(db, p['tenant'], 'cases', obj.get('case_id'))
            return self.visible(db, p, 'cases', case)
        return False

    def get(self, db, p, kind, object_id):
        obj = self.raw_object(db, p['tenant'], kind, object_id)
        require(self.visible(db, p, kind, obj), 'not_found', 'Объект не найден', 404)
        return obj

    def put(self, db, p, kind, body, action):
        db.execute('INSERT INTO objects VALUES(?,?,?,?,?) ON CONFLICT(tenant,kind,id) '
                   'DO UPDATE SET version=excluded.version,body=excluded.body',
                   (p['tenant'], kind, body['id'], body['version'], canonical(body)))
        self.audit(db, p, action, body['id'], {'version': body['version'], 'body_sha256': digest(body)})
        return body

    def base(self, p, **fields):
        return dict(id=uid(), tenant_id=p['tenant'], version=1, created_at=utc(),
                    created_by=p['subject'], **fields)

    def list(self, p, kind):
        self.authorize(p, 'audit' if kind == 'audit' else 'read')
        with self.connect() as db:
            if kind == 'audit':
                return [dict(r) | {'body': json.loads(r['body'])} for r in db.execute(
                    'SELECT seq,body,prev_hash,hash FROM audit WHERE tenant=? ORDER BY seq', (p['tenant'],))]
            items = []
            for row in db.execute('SELECT body FROM objects WHERE tenant=? AND kind=? ORDER BY id', (p['tenant'], kind)):
                obj = json.loads(row[0])
                if self.visible(db, p, kind, obj):
                    items.append(obj)
                    if len(items) == 500:
                        break
            return items

    def create_asset(self, p, body):
        self.authorize(p, 'asset')
        exact_fields(body, ['hostname', 'os', 'owner', 'criticality', 'group', 'sensitivity'], ['hostname', 'os'])
        name, os_name = text_field(body, 'hostname'), text_field(body, 'os')
        criticality = body.get('criticality', 3)
        require(type(criticality) is int and 1 <= criticality <= 5)
        for k in ('owner', 'group'):
            if k in body:
                text_field(body, k)
        sensitivity = body.get('sensitivity', 'internal')
        require(sensitivity in SENSITIVITY)
        asset = self.base(p, sensitivity=sensitivity, hostname=name, os=os_name, owner=body.get('owner', ''),
                          group=body.get('group', 'lab'), criticality=criticality, presence='unknown')
        require(asset_allowed(p, asset), 'forbidden', 'Актив вне разрешённого scope', 403)
        with self.tx() as db:
            self.live_principal(db, p)
            return self.put(db, p, 'assets', asset, 'asset.created')

    def rule(self, p, body):
        self.authorize(p, 'rule')
        exact_fields(body, ['name', 'field', 'operator', 'value', 'severity', 'technique'],
                     ['name', 'field', 'operator', 'value'])
        name = text_field(body, 'name')
        require(body['field'] in {'event_type', 'outcome', 'process_name', 'severity'})
        require(body['operator'] in {'eq', 'gte', 'contains'})
        value = body['value']
        require(type(value) in (str, int, float) and len(str(value)) <= 200)
        if body['operator'] == 'gte':
            require(type(value) in (int, float))
        if body['operator'] == 'contains':
            require(isinstance(value, str) and bool(value))
        severity = body.get('severity', 'medium')
        require(severity in {'low', 'medium', 'high', 'critical'})
        if 'technique' in body:
            text_field(body, 'technique', 40)
        rule = self.base(p, name=name, field=body['field'], operator=body['operator'], value=value,
                         severity=severity, technique=body.get('technique', ''), status='draft')
        with self.tx() as db:
            self.live_principal(db, p)
            return self.put(db, p, 'rules', rule, 'rule.created')

    @staticmethod
    def matches(rule, event):
        value = event['attributes'].get(rule['field'])
        expected = rule['value']
        if rule['operator'] == 'eq':
            return type(value) is type(expected) and value == expected
        if rule['operator'] == 'gte':
            return type(value) in (int, float) and value >= expected
        return isinstance(value, str) and expected in value

    def publish(self, p, object_id, version):
        self.authorize(p, 'publish')
        with self.tx() as db:
            self.live_principal(db, p)
            rule = self.get(db, p, 'rules', object_id)
            require(rule['version'] == version, 'version_conflict', 'Версия изменилась', 409)
            require(rule['created_by'] != p['subject'], 'self_approval', 'Нужен независимый рецензент', 403)
            require(rule['status'] == 'draft', 'invalid_state', 'Правило уже опубликовано', 409)
            rule.update(status='published', version=version+1, published_by=p['subject'])
            return self.put(db, p, 'rules', rule, 'rule.published')

    def replay(self, p, object_id):
        self.authorize(p, 'read')
        with self.connect() as db:
            rule = self.get(db, p, 'rules', object_id)
            rows = db.execute('SELECT seq,body FROM events WHERE tenant=? ORDER BY seq LIMIT 10001',
                              (p['tenant'],)).fetchall()
            require(len(rows) <= 10000, 'query_budget', 'Лимит replay — 10 000 событий', 422)
            matches = [r['seq'] for r in rows if self.matches(rule, json.loads(r['body']))]
            return {'rule_id': object_id, 'rule_version': rule['version'], 'matched_sequences': matches,
                    'scanned': len(rows), 'dry_run': True}

    def ingest(self, p, body):
        self.authorize(p, 'ingest')
        exact_fields(body, ['events'], ['events'])
        events = body['events']
        require(isinstance(events, list) and 1 <= len(events) <= 100, message='Batch: 1–100 событий')
        normalized = []
        for e in events:
            exact_fields(e, ['event_id', 'source_id', 'asset_id', 'event_time', 'attributes', 'schema_version'],
                         ['event_id', 'source_id', 'asset_id', 'event_time', 'attributes', 'schema_version'])
            for k in ('event_id', 'source_id', 'asset_id', 'event_time'):
                text_field(e, k)
            require(e['schema_version'] == 1)
            require(isinstance(e['attributes'], dict) and len(e['attributes']) <= 32)
            require(len(canonical(e).encode()) <= 16384, 'event_too_large', 'Событие больше 16 КиБ', 413)
            try:
                stamp = datetime.fromisoformat(e['event_time'].replace('Z', '+00:00'))
                require(stamp.tzinfo is not None)
                event_time = stamp.astimezone(timezone.utc).isoformat(timespec='microseconds')
            except (ValueError, TypeError):
                raise Problem(400, 'invalid_time', 'Требуется ISO 8601 с часовым поясом')
            normalized.append((e, event_time))
        accepted, duplicates = [], []
        with self.tx() as db:
            self.live_principal(db, p)
            for e, event_time in normalized:
                asset = self.get(db, p, 'assets', e['asset_id'])
                fingerprint = digest(e)
                old = db.execute('SELECT seq,digest FROM events WHERE tenant=? AND source_id=? AND event_id=?',
                                 (p['tenant'], e['source_id'], e['event_id'])).fetchone()
                if old:
                    require(old['digest'] == fingerprint, 'idempotency_conflict', 'Event ID имеет другое содержимое', 409)
                    duplicates.append(old['seq'])
                    continue
                event = dict(e, tenant_id=p['tenant'], ingest_time=utc(), event_time=event_time,
                             parser_version='canonical-v1', classification='internal', trace_id=uid())
                cur = db.execute('INSERT INTO events(tenant,source_id,event_id,event_time,body,digest) '
                                 'VALUES(?,?,?,?,?,?)', (p['tenant'], e['source_id'], e['event_id'],
                                                        event_time, canonical(event), fingerprint))
                accepted.append(cur.lastrowid)
                asset.update(last_seen=event['ingest_time'], presence='online', version=asset['version']+1)
                self.put(db, p, 'assets', asset, 'asset.heartbeat')
            self.audit(db, p, 'events.accepted', 'batch', {'accepted': len(accepted), 'duplicates': len(duplicates)})
        return {'accepted': accepted, 'duplicates': duplicates, 'durable': True, 'detection_complete': False}

    def process(self, limit=100):
        count = 0
        with self.tx() as db:
            rows = db.execute('SELECT * FROM events WHERE processed=0 ORDER BY seq LIMIT ?', (limit,)).fetchall()
            for row in rows:
                p = {'tenant': row['tenant'], 'subject': 'detection-worker', 'role': 'admin'}
                rules = [json.loads(r[0]) for r in db.execute(
                    "SELECT body FROM objects WHERE tenant=? AND kind='rules'", (p['tenant'],))]
                event = json.loads(row['body'])
                for rule in rules:
                    if rule['status'] != 'published' or not self.matches(rule, event):
                        continue
                    exists = db.execute('SELECT 1 FROM detections WHERE tenant=? AND rule_id=? '
                                        'AND rule_version=? AND event_seq=?',
                                        (p['tenant'], rule['id'], rule['version'], row['seq'])).fetchone()
                    if exists:
                        continue
                    alert = self.base(p, title=rule['name'], severity=rule['severity'], status='open',
                                      rule_id=rule['id'], rule_version=rule['version'],
                                      event_seq=row['seq'], asset_id=event['asset_id'],
                                      explanation={'field': rule['field'], 'operator': rule['operator'],
                                                   'expected': rule['value'], 'observed': event['attributes'].get(rule['field'])})
                    self.put(db, p, 'alerts', alert, 'alert.created')
                    db.execute('INSERT INTO detections VALUES(?,?,?,?,?)',
                               (p['tenant'], rule['id'], rule['version'], row['seq'], alert['id']))
                db.execute('UPDATE events SET processed=1 WHERE seq=?', (row['seq'],))
                count += 1
        return count

    def search(self, p, body):
        self.authorize(p, 'read')
        exact_fields(body, ['limit', 'after', 'event_type'])
        limit = body.get('limit', 50)
        after = body.get('after', 0)
        require(type(limit) is int and 1 <= limit <= 100)
        require(type(after) is int and after >= 0)
        query = 'SELECT seq,body FROM events WHERE tenant=? AND seq>?'
        params = [p['tenant'], after]
        if 'event_type' in body:
            text_field(body, 'event_type')
            query += " AND json_extract(body,'$.attributes.event_type')=?"
            params.append(body['event_type'])
        with self.connect() as db:
            rows = []
            for row in db.execute(query+' ORDER BY seq', params):
                event = json.loads(row['body'])
                if self.visible(db, p, 'events', event):
                    rows.append(dict(event, sequence=row['seq']))
                    if len(rows) == limit+1:
                        break
        return {'items': rows[:limit], 'next_cursor': rows[limit-1]['sequence'] if len(rows) > limit else None,
                'order': 'ingest_sequence'}

    def create_case(self, p, body, key):
        self.authorize(p, 'case')
        exact_fields(body, ['title', 'alert_id', 'owner'], ['title', 'alert_id', 'owner'])
        for field in body:
            text_field(body, field)
        require(not policy_of(p)['assigned_only'] or body['owner'] == p['subject'],
                'forbidden', 'Можно создавать только назначенные себе кейсы', 403)
        require(isinstance(key, str) and 1 <= len(key) <= 128, message='Нужен Idempotency-Key')
        with self.tx() as db:
            self.live_principal(db, p)
            old = db.execute('SELECT * FROM idempotency WHERE tenant=? AND subject=? AND operation=? AND key=?',
                             (p['tenant'], p['subject'], 'case.create', key)).fetchone()
            if old:
                require(old['digest'] == digest(body), 'idempotency_conflict', 'Ключ уже использован', 409)
                return self.get(db, p, 'cases', old['object_id'])
            self.get(db, p, 'alerts', body['alert_id'])
            case = self.base(p, **body, status='NEW', timeline=[{'time': utc(), 'actor': p['subject'], 'action': 'created'}])
            self.put(db, p, 'cases', case, 'case.created')
            db.execute('INSERT INTO idempotency VALUES(?,?,?,?,?,?)',
                       (p['tenant'], p['subject'], 'case.create', key, digest(body), case['id']))
            return case

    def transition(self, p, object_id, body, version):
        self.authorize(p, 'case')
        exact_fields(body, ['status', 'reason'], ['status', 'reason'])
        reason = text_field(body, 'reason', 2000)
        target = text_field(body, 'status')
        with self.tx() as db:
            self.live_principal(db, p)
            case = self.get(db, p, 'cases', object_id)
            require(case['version'] == version, 'version_conflict', 'Версия изменилась; обновите карточку', 409)
            require(target in STATES[case['status']], 'invalid_transition', 'Недопустимый переход', 409)
            if case['status'] == 'CLOSED':
                require(p['role'] in {'admin', 'lead'}, 'forbidden', 'Открыть закрытый кейс может IR Lead', 403)
            case['timeline'].append({'time': utc(), 'actor': p['subject'], 'from': case['status'],
                                     'to': target, 'reason': reason})
            case.update(status=target, version=version+1)
            return self.put(db, p, 'cases', case, 'case.transition')

    def response(self, p, body):
        self.authorize(p, 'request')
        exact_fields(body, ['asset_id', 'case_id', 'action', 'reason', 'ttl_seconds'],
                     ['asset_id', 'case_id', 'action', 'reason'])
        for k in ('asset_id', 'case_id', 'action', 'reason'):
            text_field(body, k, 2000)
        require(body['action'] in ACTIONS, 'action_forbidden', 'Действие отсутствует в allowlist', 422)
        ttl = body.get('ttl_seconds', 300)
        require(type(ttl) is int and 30 <= ttl <= 900)
        with self.tx() as db:
            self.live_principal(db, p)
            asset = self.get(db, p, 'assets', body['asset_id'])
            case = self.get(db, p, 'cases', body['case_id'])
            alert = self.get(db, p, 'alerts', case['alert_id'])
            require(alert['asset_id'] == asset['id'], 'scope_mismatch', 'Актив не относится к кейсу', 422)
            job = self.base(p, **body, status='PENDING_APPROVAL', approvals=[],
                            expires_at=time.time()+ttl, simulation_only=True,
                            impact={'asset_count': 1, 'criticality': asset['criticality'],
                                    'requires_quorum': 2, 'execution_enabled': False})
            return self.put(db, p, 'responses', job, 'response.requested')

    def approve(self, p, object_id, version):
        self.authorize(p, 'approve')
        with self.tx() as db:
            self.live_principal(db, p)
            job = self.get(db, p, 'responses', object_id)
            require(job['version'] == version, 'version_conflict', 'Версия изменилась', 409)
            require(job['expires_at'] > time.time(), 'expired', 'Срок согласования истёк', 409)
            require(job['status'] == 'PENDING_APPROVAL', 'invalid_state', 'Заявка уже согласована', 409)
            require(p['subject'] != job['created_by'], 'self_approval', 'Самосогласование запрещено', 403)
            require(p['subject'] not in job['approvals'], 'duplicate_approval', 'Голос уже учтён', 409)
            job['approvals'].append(p['subject'])
            job['version'] += 1
            if len(job['approvals']) >= 2:
                job['status'] = 'APPROVED'
            return self.put(db, p, 'responses', job, 'response.approved')

    def evidence(self, p, body):
        self.authorize(p, 'case')
        exact_fields(body, ['case_id', 'name', 'content'], ['case_id', 'name', 'content'])
        for k in ('case_id', 'name', 'content'):
            text_field(body, k, 65536 if k == 'content' else 200)
        raw = body['content'].encode()
        with self.tx() as db:
            self.live_principal(db, p)
            case = self.get(db, p, 'cases', body['case_id'])
            obj = self.base(p, name=body['name'], case_id=case['id'], sha256=hashlib.sha256(raw).hexdigest(),
                            size=len(raw), content_base64=base64.b64encode(raw).decode(), legal_hold=True)
            self.put(db, p, 'evidence', obj, 'evidence.acquired')
            case['timeline'].append({'time': utc(), 'actor': p['subject'], 'action': 'evidence.acquired',
                                     'evidence_id': obj['id'], 'sha256': obj['sha256']})
            case['version'] += 1
            self.put(db, p, 'cases', case, 'case.evidence_linked')
            return obj

    def export(self, p):
        self.authorize(p, 'audit')
        # One SQLite snapshot: objects and audit must describe the same committed state.
        with self.connect() as db:
            db.execute('BEGIN')
            evidence = [json.loads(r[0]) for r in db.execute(
                "SELECT body FROM objects WHERE tenant=? AND kind='evidence' ORDER BY id", (p['tenant'],))]
            audit = [dict(r) | {'body': json.loads(r['body'])} for r in db.execute(
                'SELECT seq,body,prev_hash,hash FROM audit WHERE tenant=? ORDER BY seq', (p['tenant'],))]
        return {'format': 'bastion-evidence-v1', 'tenant_id': p['tenant'], 'evidence': evidence,
                'audit': audit, 'checkpoint': audit[-1]['hash'] if audit else ZERO,
                'signature': None, 'trust': 'unanchored-local-hash-chain'}


def verify(bundle, expected_checkpoint=None):
    require(bundle.get('format') == 'bastion-evidence-v1')
    previous = ZERO
    for entry in bundle['audit']:
        require(entry['body']['tenant_id'] == bundle['tenant_id'], 'integrity_error')
        expected = hashlib.sha256((previous + canonical(entry['body'])).encode()).hexdigest()
        require(entry['prev_hash'] == previous and hmac.compare_digest(expected, entry['hash']), 'integrity_error')
        previous = expected
    require(hmac.compare_digest(previous, bundle['checkpoint']), 'integrity_error')
    if expected_checkpoint:
        require(hmac.compare_digest(previous, expected_checkpoint), 'checkpoint_mismatch')
    expected_ids = {e['body']['resource'] for e in bundle['audit'] if e['body']['action'] == 'evidence.acquired'}
    actual_ids = [obj['id'] for obj in bundle['evidence']]
    require(len(actual_ids) == len(set(actual_ids)) and set(actual_ids) == expected_ids, 'missing_evidence')
    for obj in bundle['evidence']:
        require(obj['tenant_id'] == bundle['tenant_id'], 'integrity_error')
        raw = base64.b64decode(obj['content_base64'], validate=True)
        require(hashlib.sha256(raw).hexdigest() == obj['sha256'] and len(raw) == obj['size'], 'integrity_error')
        require(any(e['body']['action'] == 'evidence.acquired' and e['body']['resource'] == obj['id']
                    and e['body']['details'].get('body_sha256') == digest(obj)
                    for e in bundle['audit']), 'missing_custody')
    return {'valid': True, 'evidence_count': len(bundle['evidence']), 'audit_count': len(bundle['audit']),
            'anchored': bool(expected_checkpoint)}
