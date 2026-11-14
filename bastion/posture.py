"""Local finding intake and audited remediation; scanner claims are not independently verified."""
from datetime import date, datetime, timezone
import json
import uuid
import time

from .analytics import timestamp
from .policy import policy_of
from .core import canonical, digest, exact_fields, require, text_field, utc

SEVERITY = {'info': 0, 'low': 3, 'medium': 8, 'high': 15, 'critical': 20}
TRANSITIONS = {
    'open': {'investigating', 'remediation_planned', 'accepted', 'false_positive'},
    'investigating': {'open', 'remediation_planned', 'accepted', 'false_positive'},
    'remediation_planned': {'investigating', 'mitigated', 'fixed', 'accepted'},
    'mitigated': {'investigating', 'remediation_planned', 'fixed', 'accepted'},
    'accepted': {'investigating'}, 'fixed': {'investigating'}, 'false_positive': {'investigating'},
}


class Posture:
    def __init__(self, store):
        self.store = store

    def ingest(self, p, body):
        self.store.authorize(p, 'publish')  # Full admin/lead; scanner source is a declared label, not an identity.
        exact_fields(body, ['source', 'observed_at', 'findings'], ['source', 'observed_at', 'findings'])
        source = text_field(body, 'source')
        observed = timestamp(body['observed_at'])
        items = body['findings']
        require(isinstance(items, list) and 1 <= len(items) <= 100)
        require(len(canonical(body).encode()) <= 262144, 'payload_size', 'Импорт ограничен 256 КиБ', 413)
        normalized, seen = [], set()
        for item in items:
            exact_fields(item, ['external_id', 'asset_id', 'title', 'component', 'component_version', 'vulnerability_id', 'severity'],
                         ['external_id', 'asset_id', 'title', 'component', 'component_version', 'vulnerability_id', 'severity'])
            record = {key: text_field(item, key) for key in item}
            require(record['severity'] in SEVERITY)
            key = (record['asset_id'], record['external_id'])
            require(key not in seen, 'duplicate_finding', 'Повтор записи внутри импорта', 409)
            seen.add(key)
            normalized.append(record)
        created, duplicates = [], []
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            for record in normalized:
                asset = self.store.get(db, p, 'assets', record['asset_id'])
                identity = digest([p['tenant'], source, record['asset_id'], record['external_id']])
                object_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'bastion-finding:'+identity))
                observation = {'source': source, 'observed_at': observed, **record}
                fingerprint = digest(observation)
                old = self.store.raw_object(db, p['tenant'], 'findings', object_id)
                if old:
                    require(old['observation_sha256'] == fingerprint, 'idempotency_conflict',
                            'Идентификатор уже связан с другим наблюдением; используйте новый external_id', 409)
                    duplicates.append(object_id)
                    continue
                finding = self.store.base(p, **observation, observation_sha256=fingerprint,
                    import_sha256=digest(body), status='open', owner='', due_date=None, history=[],
                    verification='manual-import-unverified', evidence_id=None)
                finding['id'] = object_id
                finding['history'].append({'time': utc(), 'actor': p['subject'], 'action': 'imported'})
                self.store.put(db, p, 'findings', finding, 'finding.imported')
                created.append(object_id)
        return {'created': created, 'duplicates': duplicates, 'atomic': True}

    def list(self, p):
        self.store.authorize(p, 'read')
        with self.store.connect() as db:
            db.execute('BEGIN')
            result = []
            for row in db.execute("SELECT body FROM objects WHERE tenant=? AND kind='findings' ORDER BY id", (p['tenant'],)):
                obj = json.loads(row['body'])
                if not self.store.visible(db, p, 'findings', obj):
                    continue
                require(len(result) < 500, 'query_budget', 'Более 500 доступных находок; фильтрация пока не реализована', 422)
                asset = self.store.get(db, p, 'assets', obj['asset_id'])
                score = SEVERITY[obj['severity']] * asset['criticality']
                result.append(obj | {'priority_score': score, 'asset_criticality': asset['criticality'],
                    'overdue': bool(obj['due_date'] and obj['due_date'] < datetime.now(timezone.utc).date().isoformat()
                                    and obj['status'] not in ('fixed', 'false_positive', 'accepted'))})
        return {'items': sorted(result, key=lambda x: (-x['priority_score'], x['id'])),
                'limit': 500, 'priority_model': 'severity-weight-times-asset-criticality'}

    def update(self, p, object_id, body, version):
        self.store.authorize(p, 'case')
        exact_fields(body, ['status', 'owner', 'due_date', 'reason', 'evidence_id'], ['status', 'owner', 'due_date', 'reason'])
        status, owner, reason = text_field(body, 'status'), text_field(body, 'owner'), text_field(body, 'reason', 2000)
        require(status in TRANSITIONS)
        require(not policy_of(p)['assigned_only'] or owner == p['subject'], 'forbidden', 'Доступ только к своим назначениям', 403)
        due = body['due_date']
        if due is not None:
            require(isinstance(due, str))
            try:
                require(date.fromisoformat(due).isoformat() == due)
            except ValueError:
                require(False, 'invalid_date', 'Срок должен иметь вид YYYY-MM-DD')
        if status == 'remediation_planned':
            require(due is not None, 'invalid_date', 'Для плана исправления нужен срок')
        if status in ('fixed', 'accepted', 'false_positive'):
            self.store.authorize(p, 'publish')
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            finding = self.store.get(db, p, 'findings', object_id)
            require(finding['version'] == version, 'version_conflict', 'Находка уже изменена', 409)
            require(status == finding['status'] or status in TRANSITIONS[finding['status']],
                    'invalid_transition', 'Недопустимый переход', 409)
            assigned = db.execute("SELECT * FROM identities WHERE tenant=? AND subject=? AND role IN ('admin','lead','analyst') "
                                  'AND revoked=0 AND expires>?', (p['tenant'], owner, time.time())).fetchone()
            require(assigned is not None, 'invalid_owner', 'Нужен действующий ответственный', 422)
            self.store.get(db, dict(assigned), 'assets', finding['asset_id'])
            evidence_id = body.get('evidence_id')
            if evidence_id is not None:
                require(isinstance(evidence_id, str) and bool(evidence_id))
                evidence = self.store.get(db, p, 'evidence', evidence_id)
                case = self.store.get(db, p, 'cases', evidence['case_id'])
                alert = self.store.get(db, p, 'alerts', case['alert_id'])
                require(alert['asset_id'] == finding['asset_id'], 'scope_mismatch', 'Доказательство относится к другому активу', 422)
            if status == 'fixed':
                require(evidence_id is not None, 'missing_evidence', 'Нужно доказательство проверки исправления', 422)
            finding['history'].append({'time': utc(), 'actor': p['subject'], 'from': finding['status'], 'to': status,
                                       'reason': reason, 'owner': owner, 'due_date': due, 'evidence_id': evidence_id})
            finding.update(status=status, owner=owner, due_date=due, evidence_id=evidence_id, version=version+1)
            return self.store.put(db, p, 'findings', finding, 'finding.updated')
