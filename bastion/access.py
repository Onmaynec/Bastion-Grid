"""Lab identities, policies and sessions. No simulated OIDC or MFA assurance."""
import hashlib
import json
import secrets
import sqlite3
import time

from .core import Problem, ROLES, canonical, exact_fields, require, text_field, uid
from .policy import DEFAULT_POLICY, SENSITIVITY, policy_of, unrestricted


def validate_policy(value):
    exact_fields(value, DEFAULT_POLICY.keys(), DEFAULT_POLICY.keys())
    groups = value['groups']
    require(isinstance(groups, list) and 1 <= len(groups) <= 50, message='Укажите от 1 до 50 групп')
    require(all(isinstance(g, str) and g.strip() == g and 1 <= len(g) <= 100 for g in groups))
    require(len(groups) == len(set(groups)))
    require('*' not in groups or groups == ['*'], message='Wildcard нельзя совмещать с именами групп')
    require(value['max_sensitivity'] in SENSITIVITY)
    require(type(value['assigned_only']) is bool)
    return dict(groups=sorted(groups), max_sensitivity=value['max_sensitivity'], assigned_only=value['assigned_only'])


def public_identity(row):
    return {key: row[key] for key in ('id', 'subject', 'role', 'expires', 'revoked', 'version')} | {
        'policy': json.loads(row['policy']),
        'status': 'revoked' if row['revoked'] else 'expired' if row['expires'] <= time.time() else 'active'}


class AccessControl:
    def __init__(self, store):
        self.store = store

    def manage(self, p):
        self.store.authorize(p, 'identity')
        require(unrestricted(p), 'forbidden', 'Управление доступом требует полного scope тенанта', 403)

    def list_identities(self, p):
        self.manage(p)
        with self.store.connect() as db:
            rows = db.execute('SELECT * FROM identities WHERE tenant=? ORDER BY subject LIMIT 501', (p['tenant'],)).fetchall()
        require(len(rows) <= 500, 'query_budget', 'Больше 500 identities: требуется административная выгрузка', 422)
        return {'items': [public_identity(r) for r in rows]}

    def issue(self, p, body):
        self.manage(p)
        exact_fields(body, ['subject', 'role', 'ttl_seconds', 'policy'], ['subject', 'role', 'ttl_seconds', 'policy'])
        subject = text_field(body, 'subject', 100)
        require(subject == body['subject'], message='Уберите пробелы по краям subject')
        require(isinstance(body['role'], str) and body['role'] in ROLES)
        ttl = self.ttl(body)
        policy = validate_policy(body['policy'])
        token, object_id = secrets.token_urlsafe(32), uid()
        try:
            with self.store.tx() as db:
                # Revalidate inside the write transaction to prevent concurrent revoke/rotation races.
                self.store.live_principal(db, p)
                db.execute('INSERT INTO identities(token_hash,tenant,subject,role,expires,revoked,id,version,policy) '
                           'VALUES(?,?,?,?,?,0,?,1,?)',
                           (hashlib.sha256(token.encode()).hexdigest(), p['tenant'], subject, body['role'],
                            time.time()+ttl, object_id, canonical(policy)))
                row = db.execute('SELECT * FROM identities WHERE id=?', (object_id,)).fetchone()
                self.store.audit(db, p, 'identity.created', object_id,
                                 {'subject': subject, 'role': body['role'], 'policy': policy, 'version': 1})
                return public_identity(row) | {'token': token, 'token_display': 'once'}
        except sqlite3.IntegrityError:
            raise Problem(409, 'identity_exists', 'Subject уже существует; используйте ротацию')

    @staticmethod
    def ttl(body):
        ttl = body.get('ttl_seconds')
        require(type(ttl) is int and 60 <= ttl <= 86400, message='TTL должен быть от 60 до 86400 секунд')
        return ttl

    def target(self, db, p, object_id, version):
        row = db.execute('SELECT * FROM identities WHERE tenant=? AND id=?', (p['tenant'], object_id)).fetchone()
        require(row is not None, 'not_found', 'Объект не найден', 404)
        require(row['version'] == version, 'version_conflict', 'Версия учётной записи изменилась', 409)
        return row

    def protect_last_admin(self, db, row):
        if row['role'] != 'admin' or row['revoked'] or row['expires'] <= time.time() or not unrestricted(dict(row)):
            return
        others = db.execute("SELECT * FROM identities WHERE tenant=? AND id<>? AND role='admin' "
                            'AND revoked=0 AND expires>?', (row['tenant'], row['id'], time.time())).fetchall()
        require(any(unrestricted(dict(other)) for other in others), 'last_admin',
                'Сначала создайте второго администратора с полным scope', 409)

    def change(self, p, object_id, operation, body, version):
        self.manage(p)
        require(operation in {'rotate', 'revoke', 'policy'})
        if operation == 'rotate':
            exact_fields(body, ['ttl_seconds'], ['ttl_seconds'])
            ttl = self.ttl(body)
        elif operation == 'policy':
            exact_fields(body, ['policy'], ['policy'])
            policy = validate_policy(body['policy'])
        else:
            exact_fields(body, ['reason'], ['reason'])
            text_field(body, 'reason', 1000)
        token = secrets.token_urlsafe(32) if operation == 'rotate' else None
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            row = self.target(db, p, object_id, version)
            if operation == 'revoke' or (operation == 'policy' and not unrestricted({'policy': policy})):
                self.protect_last_admin(db, row)
            db.execute('DELETE FROM sessions WHERE identity_hash=?', (row['token_hash'],))
            if operation == 'rotate':
                db.execute('UPDATE identities SET token_hash=?,expires=?,revoked=0,version=version+1 WHERE id=?',
                           (hashlib.sha256(token.encode()).hexdigest(), time.time()+ttl, object_id))
            elif operation == 'revoke':
                db.execute('UPDATE identities SET revoked=1,version=version+1 WHERE id=?', (object_id,))
            else:
                db.execute('UPDATE identities SET policy=?,version=version+1 WHERE id=?', (canonical(policy), object_id))
            updated = db.execute('SELECT * FROM identities WHERE id=?', (object_id,)).fetchone()
            self.store.audit(db, p, 'identity.'+operation, object_id,
                             {'version': updated['version'], 'subject': row['subject'], **body})
            result = public_identity(updated)
            if token:
                result |= {'token': token, 'token_display': 'once'}
            return result

    def sessions(self, p):
        with self.store.connect() as db:
            rows = db.execute('SELECT s.id,s.created_at,s.last_seen,s.expires,i.subject,i.role FROM sessions s '
                              'JOIN identities i ON i.token_hash=s.identity_hash WHERE i.tenant=? AND '
                              'i.revoked=0 AND i.expires>? AND s.expires>? '+
                              ('' if p['role'] == 'admin' and unrestricted(p) else 'AND i.subject=? ')+
                              'ORDER BY s.created_at DESC LIMIT 501',
                              (p['tenant'], time.time(), time.time())+
                              (() if p['role'] == 'admin' and unrestricted(p) else (p['subject'],))).fetchall()
        require(len(rows) <= 500, 'query_budget', 'Лимит списка сеансов превышен', 422)
        return {'items': [dict(row) for row in rows]}

    def end_session(self, p, session_id):
        with self.store.tx() as db:
            self.store.live_principal(db, p)
            row = db.execute('SELECT s.id,i.subject FROM sessions s JOIN identities i '
                             'ON i.token_hash=s.identity_hash WHERE s.id=? AND i.tenant=?',
                             (session_id, p['tenant'])).fetchone()
            require(row is not None and (row['subject'] == p['subject'] or
                    (p['role'] == 'admin' and unrestricted(p))), 'not_found', 'Объект не найден', 404)
            db.execute('DELETE FROM sessions WHERE id=?', (session_id,))
            self.store.audit(db, p, 'session.revoked', session_id, {'subject': row['subject']})
        return {'revoked': True}
