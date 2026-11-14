import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bastion.core import Store, Problem, verify, utc


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'db.sqlite'
        self.s = Store(self.path)
        self.p = {}
        self.tokens = {}
        for name, tenant, role in [('admin', 'a', 'admin'), ('analyst', 'a', 'analyst'),
                                   ('lead1', 'a', 'lead'), ('lead2', 'a', 'lead'),
                                   ('auditor', 'a', 'auditor'), ('other', 'b', 'admin')]:
            self.tokens[name] = self.s.identity(tenant, name, role)
            self.p[name] = self.s.authenticate(self.tokens[name])
        self.admin = self.p['admin']
        self.asset = self.s.create_asset(self.admin, {'hostname': 'lab-01', 'os': 'Linux'})

    def tearDown(self):
        self.tmp.cleanup()

    def event(self, n=1):
        return {'event_id': f'e{n}', 'source_id': 's1', 'asset_id': self.asset['id'],
                'event_time': '2026-11-14T10:00:00+03:00', 'schema_version': 1,
                'attributes': {'event_type': 'authentication', 'outcome': 'failure', 'severity': 4}}

    def rule(self):
        return self.s.rule(self.admin, {'name': 'Failed login', 'field': 'outcome',
                                       'operator': 'eq', 'value': 'failure', 'severity': 'high'})

    def alert(self):
        rule = self.rule()
        self.s.publish(self.p['lead1'], rule['id'], rule['version'])
        self.s.ingest(self.admin, {'events': [self.event()]})
        self.s.process()
        return self.s.list(self.admin, 'alerts')[0]

    def case(self):
        alert = self.alert()
        return self.s.create_case(self.p['analyst'], {'title': 'Investigation', 'owner': 'analyst',
                                                     'alert_id': alert['id']}, 'case-key')

    def job(self):
        case = self.case()
        return self.s.response(self.p['analyst'], {'asset_id': self.asset['id'], 'case_id': case['id'],
                                                  'action': 'isolate_host', 'reason': 'lab drill'})

    def test_read_connection_closes_on_exit(self):
        with self.s.connect() as db:
            self.assertEqual(db.execute('SELECT 1').fetchone()[0], 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')

    def test_identity_rejects_unknown_and_expired(self):
        for token in ['invalid', self.s.identity('c', 'expired', 'admin', -1)]:
            with self.assertRaises(Problem):
                self.s.authenticate(token)

    def test_revocation_immediate(self):
        with self.s.tx() as db:
            db.execute('UPDATE identities SET revoked=1 WHERE subject=?', ('admin',))
        with self.assertRaises(Problem):
            self.s.authenticate(self.tokens['admin'])

    def test_tenant_from_server_only(self):
        with self.assertRaises(Problem):
            self.s.create_asset(self.admin, {'hostname': 'x', 'os': 'Linux', 'tenant_id': 'b'})
        self.assertEqual(self.s.list(self.p['other'], 'assets'), [])

    def test_10000_scoped_reads(self):
        with self.s.connect() as db:
            for i in range(10000):
                with self.assertRaises(Problem) as e:
                    self.s.get(db, self.p['other'], ['assets', 'cases', 'responses'][i % 3], self.asset['id'])
                self.assertEqual(e.exception.status, 404)

    def test_role_denial_audited(self):
        with self.assertRaises(Problem):
            self.s.create_asset(self.p['auditor'], {'hostname': 'x', 'os': 'Linux'})
        self.assertEqual(self.s.list(self.admin, 'audit')[-1]['body']['action'], 'access.denied')

    def test_durable_ack_restart_and_dedup(self):
        body = {'events': [self.event()]}
        result = self.s.ingest(self.admin, body)
        self.assertTrue(result['durable'])
        reopened = Store(self.path)
        self.assertEqual(reopened.ingest(self.admin, body)['duplicates'], result['accepted'])
        self.assertEqual(len(reopened.search(self.admin, {})['items']), 1)

    def test_concurrent_dedup(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.s.ingest(self.admin, {'events': [self.event()]}), range(12)))
        self.assertEqual(sum(len(r['accepted']) for r in results), 1)
        self.assertEqual(sum(len(r['duplicates']) for r in results), 11)

    def test_idempotency_conflict_rolls_back_batch(self):
        self.s.ingest(self.admin, {'events': [self.event()]})
        changed = self.event()
        changed['attributes']['outcome'] = 'success'
        with self.assertRaises(Problem):
            self.s.ingest(self.admin, {'events': [self.event(2), changed]})
        self.assertEqual(len(self.s.search(self.admin, {})['items']), 1)

    def test_cross_tenant_asset_rejected_on_ingest(self):
        with self.assertRaises(Problem) as e:
            self.s.ingest(self.p['other'], {'events': [self.event()]})
        self.assertEqual(e.exception.status, 404)

    def test_bad_event_time_and_oversize(self):
        for change in [{'event_time': '2026-01-01'}, {'attributes': {'value': 'x'*17000}}, {'schema_version': 7}]:
            with self.assertRaises(Problem):
                self.s.ingest(self.admin, {'events': [self.event() | change]})

    def test_invalid_batch_is_atomic(self):
        with self.assertRaises(Problem):
            self.s.ingest(self.admin, {'events': [self.event(), self.event(2) | {'asset_id': 'missing'}]})
        self.assertEqual(self.s.search(self.admin, {})['items'], [])

    def test_search_cursor_and_filter(self):
        self.s.ingest(self.admin, {'events': [self.event(i) for i in range(10)]})
        first = self.s.search(self.admin, {'limit': 4})
        second = self.s.search(self.admin, {'after': first['next_cursor'], 'limit': 4})
        self.assertFalse(set(e['sequence'] for e in first['items']) & set(e['sequence'] for e in second['items']))
        self.assertEqual(self.s.search(self.p['other'], {'after': first['next_cursor']})['items'], [])
        self.assertEqual(self.s.search(self.admin, {'event_type': "' OR 1=1 --"})['items'], [])

    def test_rule_validation(self):
        for fields in [{'field': '__proto__'}, {'operator': 'eval'}, {'operator': 'gte', 'value': 'x'}]:
            with self.assertRaises(Problem):
                self.s.rule(self.admin, {'name': 'x', 'field': 'outcome', 'operator': 'eq', 'value': 'failure'} | fields)

    def test_no_self_publish(self):
        r = self.rule()
        with self.assertRaises(Problem):
            self.s.publish(self.admin, r['id'], 1)

    def test_rule_immutable_published(self):
        r = self.rule()
        self.s.publish(self.p['lead1'], r['id'], 1)
        with self.assertRaises(Problem):
            self.s.publish(self.p['lead2'], r['id'], 2)

    def test_detection_restart_exact_logical_effect(self):
        self.alert()
        with self.s.tx() as db:
            db.execute('UPDATE events SET processed=0')
        self.s.process()
        self.assertEqual(len(self.s.list(self.admin, 'alerts')), 1)

    def test_draft_does_not_alert_and_replay_is_deterministic(self):
        r = self.rule()
        self.s.ingest(self.admin, {'events': [self.event()]})
        self.s.process()
        self.assertEqual(self.s.list(self.admin, 'alerts'), [])
        first = self.s.replay(self.admin, r['id'])
        self.assertEqual(first, self.s.replay(self.admin, r['id']))
        self.assertEqual(len(first['matched_sequences']), 1)

    def test_case_idempotency(self):
        c = self.case()
        body = {k: c[k] for k in ('title', 'owner', 'alert_id')}
        self.assertEqual(self.s.create_case(self.p['analyst'], body, 'case-key')['id'], c['id'])
        with self.assertRaises(Problem):
            self.s.create_case(self.p['analyst'], body | {'title': 'different'}, 'case-key')

    def test_state_machine_version_and_reason(self):
        c = self.case()
        for body, version in [({'status': 'RESOLVED', 'reason': 'x'}, 1),
                              ({'status': 'TRIAGE', 'reason': ''}, 1),
                              ({'status': 'TRIAGE', 'reason': 'x'}, 99)]:
            with self.assertRaises(Problem):
                self.s.transition(self.p['analyst'], c['id'], body, version)
        updated = self.s.transition(self.p['analyst'], c['id'], {'status': 'TRIAGE', 'reason': 'review'}, 1)
        self.assertEqual(updated['version'], 2)
        self.assertEqual(len(updated['timeline']), 2)

    def test_cross_tenant_transition(self):
        c = self.case()
        with self.assertRaises(Problem) as e:
            self.s.transition(self.p['other'], c['id'], {'status': 'TRIAGE', 'reason': 'x'}, 1)
        self.assertEqual(e.exception.status, 404)

    def test_approval_quorum_and_no_execution(self):
        j = self.job()
        first = self.s.approve(self.p['lead1'], j['id'], 1)
        self.assertEqual(first['status'], 'PENDING_APPROVAL')
        with self.assertRaises(Problem):
            self.s.approve(self.p['lead1'], j['id'], 2)
        second = self.s.approve(self.p['lead2'], j['id'], 2)
        self.assertEqual(second['status'], 'APPROVED')
        self.assertTrue(second['simulation_only'])
        self.assertFalse(second['impact']['execution_enabled'])

    def test_self_approval_even_if_role_elevated(self):
        j = self.job()
        p = dict(self.p['analyst'], role='admin')
        with self.assertRaises(Problem) as e:
            self.s.approve(p, j['id'], 1)
        self.assertEqual(e.exception.code, 'self_approval')

    def test_expired_approval(self):
        j = self.job()
        with self.s.tx() as db:
            j['expires_at'] = time.time()-1
            self.s.put(db, self.admin, 'responses', j, 'test.expire')
        with self.assertRaises(Problem) as e:
            self.s.approve(self.p['lead1'], j['id'], 1)
        self.assertEqual(e.exception.code, 'expired')

    def test_no_arbitrary_command(self):
        with self.assertRaises(Problem):
            self.s.response(self.p['analyst'], {'asset_id': self.asset['id'], 'case_id': 'x',
                                              'action': 'shell', 'reason': 'x'})

    def bundle(self):
        c = self.case()
        self.s.evidence(self.p['analyst'], {'case_id': c['id'], 'name': 'log.txt', 'content': 'test evidence'})
        return self.s.export(self.p['auditor'])

    def test_evidence_export_and_offline_verifier(self):
        bundle = self.bundle()
        result = verify(bundle, bundle['checkpoint'])
        self.assertTrue(result['anchored'])
        self.assertEqual(result['evidence_count'], 1)
        self.assertEqual(self.s.export(self.p['other'])['evidence'], [])

    def test_tampered_payload_and_metadata(self):
        bundle = self.bundle()
        for field, value in [('content_base64', 'eA=='), ('name', 'changed'), ('sha256', '0'*64)]:
            altered = copy.deepcopy(bundle)
            altered['evidence'][0][field] = value
            with self.assertRaises(Problem):
                verify(altered)

    def test_audit_tamper_and_truncation(self):
        bundle = self.bundle()
        altered = copy.deepcopy(bundle)
        altered['audit'][0]['body']['actor'] = 'tampered'
        with self.assertRaises(Problem):
            verify(altered)
        altered = copy.deepcopy(bundle)
        altered['audit'].pop()
        altered['checkpoint'] = altered['audit'][-1]['hash']
        with self.assertRaises(Problem):
            verify(altered, bundle['checkpoint'])

    def test_backup_restores_cases_and_evidence(self):
        bundle = self.bundle()
        target = Path(self.tmp.name)/'backup.sqlite'
        with self.s.connect() as source, closing(sqlite3.connect(target)) as db:
            source.backup(db)
        restored = Store(target).export(self.p['auditor'])
        self.assertEqual(restored, bundle)
        self.assertTrue(verify(restored)['valid'])


if __name__ == '__main__':
    unittest.main()
