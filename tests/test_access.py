import copy
import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from bastion.core import Store, Problem, canonical, verify
from bastion.policy import DEFAULT_POLICY, policy_of
from test_core import CoreTests
from test_http import HttpTests


class AccessTests(CoreTests):
    # Reuse fixtures, not the parent suite's test methods (suite loader below removes inherited tests).
    def issue(self, subject='scoped', role='analyst', groups=None, sensitivity='internal', assigned=False):
        return self.s.access.issue(self.admin, {'subject': subject, 'role': role, 'ttl_seconds': 3600,
                   'policy': {'groups': groups or ['lab'], 'max_sensitivity': sensitivity, 'assigned_only': assigned}})

    def test_issue_lists_without_secrets(self):
        issued = self.issue()
        self.assertEqual(len(issued['token']), 43)
        listed = self.s.access.list_identities(self.admin)
        self.assertNotIn(issued['token'], json.dumps(listed))
        self.assertNotIn('token_hash', json.dumps(listed))
        self.assertEqual(self.s.authenticate(issued['token'])['subject'], 'scoped')
        with self.assertRaises(Problem):
            self.issue()

    def test_issue_rejects_tenant_and_unknown_fields(self):
        for extra in [{'tenant_id': 'other'}, {'revoked': 0}, {'version': 9}]:
            with self.assertRaises(Problem):
                self.s.access.issue(self.admin, {'subject': 'x', 'role': 'admin', 'ttl_seconds': 60,
                                                'policy': DEFAULT_POLICY} | extra)

    def test_issue_requires_unrestricted_admin(self):
        for p in [self.p['analyst'], self.p['lead1'], self.p['auditor']]:
            with self.assertRaises(Problem):
                self.s.access.list_identities(p)
        scoped = self.issue(role='admin')
        with self.assertRaises(Problem):
            self.s.access.issue(self.s.authenticate(scoped['token']),
                                {'subject': 'escape', 'role': 'admin', 'ttl_seconds': 3600, 'policy': DEFAULT_POLICY})

    def test_policy_validation(self):
        for patch in [{'groups': []}, {'groups': ['*', 'lab']}, {'groups': ['lab', 'lab']},
                      {'assigned_only': 'false'}, {'max_sensitivity': 'secret'}, {'groups': [' lab']}]:
            with self.assertRaises(Problem):
                self.s.access.issue(self.admin, {'subject': 'invalid', 'role': 'analyst', 'ttl_seconds': 3600,
                                                'policy': DEFAULT_POLICY | patch})

    def test_rotation_old_key_invalid_and_does_not_log_secret(self):
        obj = self.issue()
        updated = self.s.access.change(self.admin, obj['id'], 'rotate', {'ttl_seconds': 100}, 1)
        self.assertEqual(updated['version'], 2)
        self.assertEqual(updated['id'], obj['id'])
        with self.assertRaises(Problem):
            self.s.authenticate(obj['token'])
        self.assertEqual(self.s.authenticate(updated['token'])['subject'], 'scoped')
        audit = json.dumps(self.s.list(self.admin, 'audit'))
        self.assertNotIn(obj['token'], audit)
        self.assertNotIn(updated['token'], audit)

    def test_revoke_and_reactivate_via_rotation(self):
        obj = self.issue()
        revoked = self.s.access.change(self.admin, obj['id'], 'revoke', {'reason': 'access ended'}, 1)
        self.assertEqual(revoked['status'], 'revoked')
        with self.assertRaises(Problem):
            self.s.authenticate(obj['token'])
        rotated = self.s.access.change(self.admin, obj['id'], 'rotate', {'ttl_seconds': 60}, 2)
        self.assertEqual(rotated['status'], 'active')

    def test_identity_if_match_and_cross_tenant(self):
        obj = self.issue()
        for p, version, code in [(self.admin, 8, 'version_conflict'), (self.p['other'], 1, 'not_found')]:
            with self.assertRaises(Problem) as e:
                self.s.access.change(p, obj['id'], 'revoke', {'reason': 'x'}, version)
            self.assertEqual(e.exception.code, code)

    def test_last_admin_guard(self):
        with self.assertRaises(Problem) as e:
            self.s.access.change(self.admin, self.admin['id'], 'revoke', {'reason': 'x'}, 1)
        self.assertEqual(e.exception.code, 'last_admin')
        with self.assertRaises(Problem):
            self.s.access.change(self.admin, self.admin['id'], 'policy',
                                 {'policy': DEFAULT_POLICY | {'groups': ['lab']}}, 1)
        self.issue('backup-admin', role='admin', groups=['*'], sensitivity='restricted')
        self.s.access.change(self.admin, self.admin['id'], 'revoke', {'reason': 'transferred'}, 1)

    def test_stale_principal_cannot_mutate_after_revocation(self):
        obj = self.issue(role='admin', groups=['*'], sensitivity='restricted')
        old = self.s.authenticate(obj['token'])
        self.s.access.change(self.admin, obj['id'], 'revoke', {'reason': 'x'}, 1)
        with self.assertRaises(Problem) as e:
            self.s.create_asset(old, {'hostname': 'blocked', 'os': 'Linux'})
        self.assertEqual(e.exception.status, 401)

    def test_policy_change_blocks_inflight_request(self):
        obj = self.issue(role='admin', groups=['*'], sensitivity='restricted')
        old = self.s.authenticate(obj['token'])
        self.s.access.change(self.admin, obj['id'], 'policy', {'policy': DEFAULT_POLICY | {'groups': ['lab']}}, 1)
        with self.assertRaises(Problem):
            self.s.create_asset(old, {'hostname': 'stale', 'os': 'Linux'})

    def test_asset_group_and_sensitivity_filter(self):
        self.s.create_asset(self.admin, {'hostname': 'hidden-a', 'os': 'Linux', 'group': 'production'})
        self.s.create_asset(self.admin, {'hostname': 'hidden-b', 'os': 'Linux', 'sensitivity': 'restricted'})
        p = self.s.authenticate(self.issue()['token'])
        self.assertEqual([x['id'] for x in self.s.list(p, 'assets')], [self.asset['id']])
        self.assertEqual(self.s.list(self.p['other'], 'assets'), [])

    def test_scoped_admin_cannot_create_outside_scope(self):
        p = self.s.authenticate(self.issue(role='admin')['token'])
        for field in [{'group': 'production'}, {'sensitivity': 'restricted'}]:
            with self.assertRaises(Problem):
                self.s.create_asset(p, {'hostname': 'outside', 'os': 'Linux'} | field)

    def test_events_alerts_cases_evidence_responses_share_scope(self):
        case = self.case()
        self.s.evidence(self.p['analyst'], {'case_id': case['id'], 'name': 'note', 'content': 'classified'})
        self.s.response(self.p['analyst'], {'case_id': case['id'], 'asset_id': self.asset['id'],
                                          'action': 'collect_metadata', 'reason': 'investigate'})
        p = self.s.authenticate(self.issue(groups=['other'])['token'])
        for kind in ['assets', 'alerts', 'cases', 'evidence', 'responses']:
            self.assertEqual(self.s.list(p, kind), [])
        self.assertEqual(self.s.search(p, {})['items'], [])
        with self.assertRaises(Problem):
            self.s.transition(p, case['id'], {'status': 'TRIAGE', 'reason': 'x'}, 1)
        with self.assertRaises(Problem):
            self.s.evidence(p, {'case_id': case['id'], 'name': 'x', 'content': 'x'})

    def test_assigned_only_cases_and_related_objects(self):
        case = self.case()  # owner = analyst
        obj = self.issue(assigned=True)
        p = self.s.authenticate(obj['token'])
        self.assertEqual(self.s.list(p, 'cases'), [])
        own = self.s.create_case(p, {'title': 'Mine', 'owner': 'scoped', 'alert_id': case['alert_id']}, 'mine')
        self.assertEqual([x['id'] for x in self.s.list(p, 'cases')], [own['id']])
        with self.assertRaises(Problem):
            self.s.create_case(p, {'title': 'Not mine', 'owner': 'analyst', 'alert_id': case['alert_id']}, 'not-mine')

    def test_audit_export_rules_replay_cannot_bypass_scopes(self):
        rule = self.rule()
        p = self.s.authenticate(self.issue(role='admin')['token'])
        self.assertEqual(self.s.list(p, 'rules'), [])
        for operation in [lambda: self.s.export(p), lambda: self.s.list(p, 'audit'),
                          lambda: self.s.replay(p, rule['id']), lambda: self.s.publish(p, rule['id'], 1)]:
            with self.assertRaises(Problem):
                operation()

    def test_collector_scope_enforced(self):
        p = self.s.authenticate(self.issue(role='collector', groups=['different'])['token'])
        with self.assertRaises(Problem):
            self.s.ingest(p, {'events': [self.event()]})
        self.assertEqual(self.s.search(self.admin, {})['items'], [])

    def test_policy_corruption_denies(self):
        for raw in ['invalid JSON', None, '{}', '{"groups":["*"]}']:
            p = dict(self.admin, policy=raw)
            self.assertEqual(self.s.list(p, 'assets'), [])

    def test_search_filters_before_page_boundary(self):
        hidden = self.s.create_asset(self.admin, {'hostname': 'hidden', 'os': 'Linux', 'group': 'other'})
        self.s.ingest(self.admin, {'events': [self.event(i) | {'asset_id': hidden['id'] if i%2 else self.asset['id']}
                                            for i in range(12)]})
        p = self.s.authenticate(self.issue()['token'])
        page1 = self.s.search(p, {'limit': 3})
        page2 = self.s.search(p, {'limit': 3, 'after': page1['next_cursor']})
        self.assertEqual(len(page1['items'])+len(page2['items']), 6)
        self.assertIsNone(page2['next_cursor'])
        self.assertTrue(all(x['asset_id'] == self.asset['id'] for x in page1['items']+page2['items']))


class MigrationTests(unittest.TestCase):
    def test_v1_upgrade_preserves_data_and_keys_closes_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'legacy.sqlite'
            db = sqlite3.connect(path)
            db.executescript(Path('bastion/schema.sql').read_text(encoding='utf-8'))
            token_hash = hashlib.sha256(b'legacy-key').hexdigest()
            db.execute('INSERT INTO identities VALUES(?,?,?,?,?,?)', (token_hash, 'legacy', 'owner', 'admin', time.time()+300, 0))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('old-session', token_hash, 'csrf', time.time()+300))
            body = {'id': 'asset', 'version': 1, 'hostname': 'legacy', 'group': 'lab'}
            db.execute('INSERT INTO objects VALUES(?,?,?,?,?)', ('legacy', 'assets', 'asset', 1, canonical(body)))
            db.commit(); db.close()
            s = Store(path)
            self.assertIsNotNone(s.migration_backup)
            snapshot = sqlite3.connect(s.migration_backup)
            self.assertEqual(snapshot.execute('SELECT MAX(version) FROM schema_version').fetchone()[0], 1)
            self.assertEqual(snapshot.execute('SELECT COUNT(*) FROM sessions').fetchone()[0], 1)
            snapshot.close()
            p = s.authenticate('legacy-key')
            self.assertEqual(s.list(p, 'assets')[0]['hostname'], 'legacy')
            self.assertEqual(s.access.sessions(p)['items'], [])
            self.assertEqual(policy_of(p), DEFAULT_POLICY)
            Store(path)  # idempotent; no second ALTER or key rotation
            self.assertEqual(s.authenticate('legacy-key')['id'], p['id'])

    def test_future_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'future.sqlite'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE schema_version(version INTEGER PRIMARY KEY)')
                db.execute('INSERT INTO schema_version VALUES(999)')
            db.close()
            with self.assertRaises(RuntimeError):
                Store(path)


class AccessHttpTests(HttpTests):
    def test_sessions_list_hides_secrets(self):
        h = self.login()
        status, _, raw = self.request('/api/v1/sessions', headers=h)
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(raw)['items']), 1)
        self.assertNotIn('csrf', raw.decode())
        self.assertNotIn('token_hash', raw.decode())

    def test_revoke_one_session_keeps_other(self):
        first, second = self.login(), self.login()
        sessions = json.loads(self.request('/api/v1/sessions', headers=first)[2])['items']
        oldest = min(sessions, key=lambda s: s['created_at'])
        self.assertEqual(self.request(f'/api/v1/sessions/{oldest["id"]}/revoke', 'POST', {}, second)[0], 200)
        self.assertEqual(self.request('/api/v1/assets', headers=first)[0], 401)
        self.assertEqual(self.request('/api/v1/assets', headers=second)[0], 200)

    def test_rotation_invalidates_all_target_cookies_and_old_bearer(self):
        h = self.login()
        p = self.s.authenticate(self.token)
        status, _, raw = self.request(f'/api/v1/identities/{p["id"]}/rotate', 'POST', {'ttl_seconds': 300},
                                     h | {'If-Match': '1'})
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/api/v1/assets', headers=h)[0], 401)
        self.assertEqual(self.request('/api/v1/assets', headers={'Authorization': 'Bearer '+self.token})[0], 401)
        new = json.loads(raw)['token']
        self.assertEqual(self.request('/api/v1/assets', headers={'Authorization': 'Bearer '+new})[0], 200)

    def test_identity_policy_change_closes_cookie(self):
        h = self.login()
        issued = self.s.access.issue(self.s.authenticate(self.token), {'subject': 'reader', 'role': 'analyst',
                     'ttl_seconds': 300, 'policy': DEFAULT_POLICY})
        _, headers, _ = self.request('/api/v1/session', 'POST', {'token': issued['token']})
        reader_cookie = {'Cookie': headers['Set-Cookie'].split(';')[0]}
        self.s.access.change(self.s.authenticate(self.token), issued['id'], 'policy',
                             {'policy': DEFAULT_POLICY | {'groups': ['other']}}, 1)
        self.assertEqual(self.request('/api/v1/assets', headers=reader_cookie)[0], 401)

    def test_own_session_cannot_end_other_user_session(self):
        admin = self.login()
        token = self.s.identity('a', 'reader', 'analyst')
        _, headers, raw = self.request('/api/v1/session', 'POST', {'token': token})
        reader = {'Cookie': headers['Set-Cookie'].split(';')[0], 'X-CSRF-Token': json.loads(raw)['csrf']}
        admin_sessions = json.loads(self.request('/api/v1/sessions', headers=admin)[2])['items']
        admin_session = next(x for x in admin_sessions if x['subject'] == 'admin')
        self.assertEqual(self.request(f'/api/v1/sessions/{admin_session["id"]}/revoke', 'POST', {}, reader)[0], 404)
        self.assertEqual(len(json.loads(self.request('/api/v1/sessions', headers=reader)[2])['items']), 1)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in [AccessTests, MigrationTests, AccessHttpTests]:
        for name in cls.__dict__:
            if name.startswith('test_'):
                suite.addTest(cls(name))
    return suite
