import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from bastion.core import Store, Problem, canonical
from bastion.telemetry import DEFAULT_QUOTAS
from test_core import CoreTests
from test_http import HttpTests


class TelemetryTests(CoreTests):
    def setUp(self):
        super().setUp()
        clock = patch('bastion.telemetry.time.time', return_value=time.time())
        clock.start()
        self.addCleanup(clock.stop)

    def collector(self, subject='collector', tenant='a'):
        return self.s.authenticate(self.s.identity(tenant, subject, 'collector'))

    def source(self, collector=None, source_id='s1', assets=None):
        collector = collector or self.collector()
        source = self.s.telemetry.create_source(self.admin, {'source_id': source_id, 'name': 'Lab source',
                  'collector_id': collector['id'], 'asset_ids': assets or [self.asset['id']]})
        return collector, source

    def quota(self, **overrides):
        q = self.s.telemetry.quotas(self.admin)
        return self.s.telemetry.set_quotas(self.admin, {k: q[k] for k in DEFAULT_QUOTAS} | overrides, q['version'])

    def dead(self, failure=None):
        self.s.ingest(self.admin, {'events': [self.event()]})
        with patch.object(self.s, 'detect_event', side_effect=failure or ValueError('secret raw payload')):
            for _ in range(3):
                self.s.process()
                with self.s.tx() as db:
                    db.execute('UPDATE events SET next_attempt=0')
        return self.s.telemetry.dead_letters(self.admin)['items'][0]

    def test_registered_source_binds_collector_and_assets(self):
        collector, source = self.source()
        ack = self.s.ingest(collector, {'events': [self.event()]})
        self.assertEqual(len(ack['accepted']), 1)
        self.s.ingest(collector, {'events': [self.event()]})
        stats = self.s.telemetry.sources(self.admin)['items'][0]
        self.assertEqual((stats['accepted_count'], stats['duplicate_count']), (1, 1))
        self.assertIsNotNone(stats['last_seen'])
        event = self.s.search(self.admin, {})['items'][0]
        self.assertEqual(event['origin'], {'identity_id': collector['id'], 'mode': 'collector'})

    def test_unregistered_collector_denied(self):
        with self.assertRaises(Problem) as e:
            self.s.ingest(self.collector(), {'events': [self.event()]})
        self.assertEqual(e.exception.code, 'source_forbidden')

    def test_admin_cannot_spoof_registered_collector(self):
        self.source()
        with self.assertRaises(Problem):
            self.s.ingest(self.admin, {'events': [self.event()]})

    def test_other_collector_and_asset_denied(self):
        collector, source = self.source()
        other = self.collector('other-collector')
        asset = self.s.create_asset(self.admin, {'hostname': 'unbound', 'os': 'Linux'})
        for p, e in [(other, self.event()), (collector, self.event() | {'asset_id': asset['id']})]:
            with self.assertRaises(Problem):
                self.s.ingest(p, {'events': [e]})

    def test_source_registration_cannot_expand_collector_scope(self):
        issued = self.s.access.issue(self.admin, {'subject': 'scoped-collector', 'role': 'collector', 'ttl_seconds': 300,
                   'policy': {'groups': ['other'], 'max_sensitivity': 'internal', 'assigned_only': False}})
        with self.assertRaises(Problem):
            self.source(self.s.authenticate(issued['token']))

    def test_source_registration_ownership_and_duplicates(self):
        collector, source = self.source()
        with self.assertRaises(Problem) as e:
            self.source(collector)
        self.assertEqual(e.exception.code, 'source_exists')
        foreign = self.collector('foreign', tenant='b')
        with self.assertRaises(Problem):
            self.source(foreign, source_id='other-source')

    def test_pause_resume_and_version(self):
        collector, source = self.source()
        paused = self.s.telemetry.source_state(self.admin, source['id'], {'enabled': False, 'reason': 'maintenance'}, 1)
        self.assertEqual(paused['version'], 2)
        with self.assertRaises(Problem):
            self.s.ingest(collector, {'events': [self.event()]})
        with self.assertRaises(Problem):
            self.s.telemetry.source_state(self.admin, source['id'], {'enabled': True, 'reason': 'ready'}, 1)
        self.s.telemetry.source_state(self.admin, source['id'], {'enabled': True, 'reason': 'ready'}, 2)
        self.assertEqual(len(self.s.ingest(collector, {'events': [self.event()]})['accepted']), 1)

    def test_collector_rotation_keeps_binding(self):
        collector, source = self.source()
        rotated = self.s.access.change(self.admin, collector['id'], 'rotate', {'ttl_seconds': 300}, 1)
        current = self.s.authenticate(rotated['token'])
        self.assertEqual(len(self.s.ingest(current, {'events': [self.event()]})['accepted']), 1)

    def test_source_cross_tenant_hidden(self):
        _, source = self.source()
        self.assertEqual(self.s.telemetry.sources(self.p['other'])['items'], [])
        with self.assertRaises(Problem) as e:
            self.s.telemetry.source_state(self.p['other'], source['id'], {'enabled': False, 'reason': 'x'}, 1)
        self.assertEqual(e.exception.status, 404)

    def test_admission_quota_batch_atomic(self):
        self.quota(max_events_per_minute=1)
        with self.assertRaises(Problem) as e:
            self.s.ingest(self.admin, {'events': [self.event(1), self.event(2)]})
        self.assertEqual(e.exception.code, 'rate_limited')
        self.assertEqual(self.s.search(self.admin, {})['items'], [])
        self.assertEqual(self.s.list(self.admin, 'assets')[0]['version'], 1)

    def test_duplicates_free_under_exhausted_quota(self):
        self.quota(max_events_per_minute=1, max_pending=1)
        first = self.s.ingest(self.admin, {'events': [self.event()]})
        repeat = self.s.ingest(self.admin, {'events': [self.event()]})
        self.assertEqual(repeat['duplicates'], first['accepted'])
        with self.assertRaises(Problem):
            self.s.ingest(self.admin, {'events': [self.event(2)]})

    def test_backpressure_relieved_after_processing(self):
        self.quota(max_pending=1)
        self.s.ingest(self.admin, {'events': [self.event()]})
        with self.assertRaises(Problem) as e:
            self.s.ingest(self.admin, {'events': [self.event(2)]})
        self.assertEqual(e.exception.code, 'backpressure')
        self.s.process()
        self.s.ingest(self.admin, {'events': [self.event(2)]})
        self.assertEqual(self.s.telemetry.health(self.admin)['counts']['pending'], 1)

    def test_daily_byte_quota_uses_utf8(self):
        self.quota(max_bytes_per_day=1024)
        e = self.event() | {'attributes': {'message': 'Я'*600}}
        with self.assertRaises(Problem) as problem:
            self.s.ingest(self.admin, {'events': [e]})
        self.assertEqual(problem.exception.code, 'daily_quota')
        self.assertEqual(self.s.telemetry.health(self.admin)['stored_events'], 0)

    def test_quota_counters_persist_on_restart(self):
        self.quota(max_events_per_minute=1)
        self.s.ingest(self.admin, {'events': [self.event()]})
        reopened = Store(self.path)
        with self.assertRaises(Problem):
            reopened.ingest(self.admin, {'events': [self.event(2)]})

    def test_quota_concurrency_cannot_oversubscribe(self):
        self.quota(max_events_per_minute=2)
        def send(i):
            try:
                self.s.ingest(self.admin, {'events': [self.event(i)]})
                return True
            except Problem:
                return False
        with ThreadPoolExecutor(max_workers=6) as executor:
            outcomes = list(executor.map(send, range(6)))
        self.assertEqual(sum(outcomes), 2)

    def test_one_tenant_quota_does_not_block_another(self):
        self.quota(max_events_per_minute=1)
        self.s.ingest(self.admin, {'events': [self.event()]})
        foreign_asset = self.s.create_asset(self.p['other'], {'hostname': 'b', 'os': 'Linux'})
        self.s.ingest(self.p['other'], {'events': [self.event() | {'asset_id': foreign_asset['id']}]})
        self.assertEqual(self.s.telemetry.health(self.p['other'])['stored_events'], 1)

    def test_quota_window_rollover(self):
        self.quota(max_events_per_minute=1)
        now = time.time()
        with patch('bastion.telemetry.time.time', return_value=now):
            self.s.ingest(self.admin, {'events': [self.event()]})
        with patch('bastion.telemetry.time.time', return_value=now+61):
            self.s.ingest(self.admin, {'events': [self.event(2)]})

    def test_bad_quota_and_stale_version(self):
        for value in [0, True, -1, 1000001]:
            with self.assertRaises(Problem):
                self.quota(max_pending=value)
        self.quota(max_pending=2)
        with self.assertRaises(Problem):
            self.s.telemetry.set_quotas(self.admin, DEFAULT_QUOTAS, 1)

    def test_poison_event_does_not_rollback_healthy_event(self):
        self.s.ingest(self.admin, {'events': [self.event(1), self.event(2)]})
        original = self.s.detect_event
        def faulty(db, row):
            if row['event_id'] == 'e1':
                raise ValueError('sensitive exception content')
            return original(db, row)
        with patch.object(self.s, 'detect_event', side_effect=faulty):
            self.assertEqual(self.s.process(), 1)
        health = self.s.telemetry.health(self.admin)
        self.assertEqual(health['counts']['done'], 1)
        self.assertEqual(health['counts']['retry'], 1)
        self.assertNotIn('sensitive exception content', canonical(self.s.list(self.admin, 'audit')))

    def test_three_attempts_dead_letter_and_redacted_metadata(self):
        row = self.dead()
        self.assertEqual(row['attempts'], 3)
        self.assertEqual(row['error_code'], 'detection_error')
        self.assertNotIn('body', row)
        self.assertEqual(self.s.process(), 0)
        self.assertEqual(self.s.telemetry.health(self.admin)['counts']['dead'], 1)

    def test_retry_schedule_prevents_hot_loop(self):
        self.s.ingest(self.admin, {'events': [self.event()]})
        with patch.object(self.s, 'detect_event', side_effect=ValueError('test')) as worker:
            self.s.process()
            self.s.process()
            self.assertEqual(worker.call_count, 1)

    def test_manual_retry_does_not_duplicate_logical_effects(self):
        rule = self.rule()
        self.s.publish(self.p['lead1'], rule['id'], 1)
        original = self.s.detect_event
        def fail_after_effect(db, row):
            original(db, row)
            raise ValueError('rollback partial effects')
        row = self.dead(fail_after_effect)
        self.assertEqual(self.s.list(self.admin, 'alerts'), [])
        queued = self.s.telemetry.retry_dead(self.admin, row['seq'], {'reason': 'handler fixed'}, row['work_revision'])
        self.assertEqual(queued['state'], 'pending')
        self.assertEqual(Store(self.path).process(), 1)
        self.assertEqual(len(self.s.list(self.admin, 'alerts')), 1)
        self.assertEqual(self.s.process(), 0)

    def test_storage_failure_is_not_dead_letter(self):
        self.s.ingest(self.admin, {'events': [self.event()]})
        with patch.object(self.s, 'detect_event', side_effect=sqlite3.OperationalError('disk unavailable')):
            with self.assertRaises(sqlite3.OperationalError):
                self.s.process()
        self.assertEqual(self.s.telemetry.health(self.admin)['counts']['pending'], 1)
        self.assertEqual(self.s.telemetry.dead_letters(self.admin)['items'], [])

    def test_dead_letter_scope_and_version(self):
        row = self.dead()
        self.assertEqual(self.s.telemetry.dead_letters(self.p['other'])['items'], [])
        for p, version in [(self.p['other'], row['work_revision']), (self.admin, 999)]:
            with self.assertRaises(Problem):
                self.s.telemetry.retry_dead(p, row['seq'], {'reason': 'x'}, version)

    def test_processing_round_robin(self):
        other_asset = self.s.create_asset(self.p['other'], {'hostname': 'other', 'os': 'Linux'})
        self.s.ingest(self.admin, {'events': [self.event(i) for i in range(10)]})
        self.s.ingest(self.p['other'], {'events': [self.event() | {'asset_id': other_asset['id']}]})
        self.s.process(limit=2)
        self.assertEqual(self.s.telemetry.health(self.admin)['counts']['done'], 1)
        self.assertEqual(self.s.telemetry.health(self.p['other'])['counts']['done'], 1)

    def test_health_and_controls_require_role_and_full_scope(self):
        with self.assertRaises(Problem):
            self.s.telemetry.health(self.p['analyst'])
        with self.assertRaises(Problem):
            self.s.telemetry.set_quotas(self.p['auditor'], DEFAULT_QUOTAS, 1)
        self.assertEqual(self.s.telemetry.health(self.p['auditor'])['stored_events'], 0)

    def test_source_counters_rollback_on_rejected_batch(self):
        collector, source = self.source()
        self.quota(max_events_per_minute=1)
        with self.assertRaises(Problem):
            self.s.ingest(collector, {'events': [self.event(1), self.event(2)]})
        row = self.s.telemetry.sources(self.admin)['items'][0]
        self.assertEqual(row['accepted_count'], 0)
        self.assertIsNone(row['last_seen'])

    def test_two_workers_keep_single_detection_effect(self):
        self.alert()
        with self.s.tx() as db:
            db.execute("UPDATE events SET processed=0,work_state='pending'")
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: Store(self.path).process(), range(2)))
        self.assertEqual(len(self.s.list(self.admin, 'alerts')), 1)

    def test_dead_letter_retry_obeys_pending_capacity(self):
        dead = self.dead()
        self.quota(max_pending=1)
        self.s.ingest(self.admin, {'events': [self.event(2)]})
        with self.assertRaises(Problem) as e:
            self.s.telemetry.retry_dead(self.admin, dead['seq'], {'reason': 'retry'}, dead['work_revision'])
        self.assertEqual(e.exception.code, 'backpressure')
        self.assertEqual(len(self.s.telemetry.dead_letters(self.admin)['items']), 1)


class TelemetryHttpTests(HttpTests):
    def test_health_routes_and_error_contract(self):
        h = self.login()
        status, _, body = self.request('/api/v1/telemetry/health', headers=h)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['counts']['dead'], 0)
        self.assertEqual(self.request('/api/v1/telemetry/dead-letters?limit=101', headers=h)[0], 400)
        self.assertEqual(self.request('/api/v1/telemetry/sources', headers=h)[0], 200)
        self.assertEqual(self.request('/api/v1/telemetry/quotas', 'POST', DEFAULT_QUOTAS, h)[0], 428)

    def test_http_backpressure_has_retry_after(self):
        h = self.login()
        p = self.s.authenticate(self.token)
        self.s.telemetry.set_quotas(p, DEFAULT_QUOTAS | {'max_events_per_minute': 1}, 1)
        asset = self.s.create_asset(p, {'hostname': 'x', 'os': 'Linux'})
        e = {'source_id': 'synthetic', 'event_id': 'one', 'asset_id': asset['id'], 'event_time': '2026-11-14T07:00:00Z',
             'schema_version': 1, 'attributes': {'event_type': 'lab'}}
        self.assertEqual(self.request('/api/v1/events/ingest', 'POST', {'events': [e]}, h)[0], 200)
        status, headers, body = self.request('/api/v1/events/ingest', 'POST', {'events': [e | {'event_id':'two'}]}, h)
        self.assertEqual(status, 429)
        self.assertEqual(headers['Retry-After'], '60')
        self.assertEqual(json.loads(body)['error_code'], 'rate_limited')


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for cls in [TelemetryTests, TelemetryHttpTests]:
        for name in cls.__dict__:
            if name.startswith('test_'):
                suite.addTest(cls(name))
    return suite
