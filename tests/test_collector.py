import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from bastion.collector import Collector, CollectorError, config_file, transport
from bastion.core import Store
from bastion.server import Server


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_path = self.root/'collector.json'
        self.raw = {'url': 'http://127.0.0.1:8080', 'source_id': 'local-test', 'asset_id': 'asset-1',
                    'token_file': 'key.txt', 'spool': 'spool.sqlite3'}
        self.config_path.write_text(json.dumps(self.raw))
        (self.root/'key.txt').write_text('fake-key')
        self.config = config_file(self.config_path)
        self.c = Collector(self.config)

    def queued(self):
        with self.c.db() as db:
            return [json.loads(r[0]) for r in db.execute('SELECT body FROM queue ORDER BY seq')]

    @staticmethod
    def ack(config, event):
        return 200, {'durable': True, 'accepted': [1], 'duplicates': []}, None

    def test_collector_restart_preserves_event_ids(self):
        self.c.sample()
        event = self.queued()[0]
        self.c = Collector(self.config)
        self.assertEqual(self.queued(), [event])
        self.assertEqual(self.c.flush(send=self.ack), 1)
        self.assertEqual(self.c.status()['queued'], 0)

    def test_collector_queue_cap_preserves_oldest(self):
        self.c = Collector(self.config, max_events=2)
        self.assertTrue(self.c.sample()); self.assertTrue(self.c.sample())
        events = self.queued()
        self.assertFalse(self.c.sample())
        self.assertEqual(self.queued(), events)
        self.assertEqual(self.c.status()['counters']['dropped'], 1)

    def test_collector_byte_cap(self):
        self.c = Collector(self.config, max_bytes=1024)
        for _ in range(10):
            self.c.sample()
        self.assertLessEqual(self.c.status()['payload_bytes'], 1024)
        self.assertGreater(self.c.status()['counters']['dropped'], 0)

    def test_collector_concurrent_cap(self):
        self.c = Collector(self.config, max_events=3)
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: self.c.sample(), range(10)))
        self.assertEqual(sum(results), 3)
        self.assertEqual(self.c.status()['counters']['dropped'], 7)

    def test_collector_binding_cannot_change(self):
        for field in ['url', 'asset_id', 'source_id']:
            with self.assertRaises(CollectorError):
                Collector(self.config | {field: 'different'})
        Collector(self.config | {'token_file': str(self.root/'rotated.txt')})

    def test_collector_rejects_remote_and_ambiguous_urls(self):
        for url in ['https://127.0.0.1', 'http://localhost:8080', 'http://example.com',
                    'http://127.0.0.1@evil.test', 'http://127.0.0.1/x', 'http://127.0.0.1?x=y',
                    'http://user:pass@127.0.0.1', 'http://127.0.0.1:99999']:
            self.config_path.write_text(json.dumps(self.raw | {'url': url}))
            with self.assertRaises(CollectorError):
                config_file(self.config_path)

    def test_collector_paths_are_relative_to_config(self):
        self.assertEqual(self.config['token_file'], str((self.root/'key.txt').resolve()))
        self.assertEqual(self.config['spool'], str((self.root/'spool.sqlite3').resolve()))

    def test_collector_allowlisted_observation(self):
        self.c.sample()
        event = self.queued()[0]
        self.assertEqual(set(event['attributes']), {'event_type', 'collector_version', 'os_family', 'os_release',
                         'architecture', 'python_version', 'profile'})
        self.assertEqual(event['source_id'], self.raw['source_id'])
        self.assertNotIn('fake-key', json.dumps(event))

    def test_collector_bad_ack_never_deletes(self):
        self.c.sample()
        for body in [{}, {'durable': False, 'accepted': [1], 'duplicates': []},
                     {'durable': True, 'accepted': [], 'duplicates': []},
                     {'durable': True, 'accepted': [True], 'duplicates': []},
                     {'durable': True, 'accepted': [1, 2], 'duplicates': []}]:
            with self.c.db() as db:
                db.execute('UPDATE queue SET next_attempt=0')
            self.assertEqual(self.c.flush(send=lambda c,e: (200, body, None)), 0)
            self.assertEqual(self.c.status()['queued'], 1)

    def test_collector_429_backoff_persists(self):
        self.c.sample()
        with patch('bastion.collector.time.time', return_value=1000):
            self.c.flush(send=lambda c,e: (429, {}, 60))
            self.c = Collector(self.config)
            self.assertEqual(self.c.status()['next_attempt'], 1060)
            self.assertEqual(self.c.flush(send=self.ack), 0)
        with patch('bastion.collector.time.time', return_value=1060):
            self.assertEqual(self.c.flush(send=self.ack), 1)

    def test_collector_permanent_error_requires_manual_retry(self):
        self.c.sample(); self.c.sample()
        self.c.flush(send=lambda c,e: (403, {}, None))
        self.assertEqual(self.c.status()['blocked'], 1)
        self.assertEqual(self.c.flush(send=self.ack), 0)
        self.assertEqual(self.c.retry_blocked(), 1)
        self.assertEqual(self.c.flush(send=self.ack), 2)

    def test_collector_lost_ack_replays_identical_event(self):
        self.c.sample()
        seen = []
        def lost(c,e):
            seen.append(e)
            return 503, {}, None
        self.c.flush(send=lost)
        with self.c.db() as db:
            db.execute('UPDATE queue SET next_attempt=0')
        def duplicate(c,e):
            self.assertEqual(e, seen[0])
            return 200, {'durable': True, 'accepted': [], 'duplicates': [1]}, None
        self.assertEqual(self.c.flush(send=duplicate), 1)
        self.assertEqual(self.c.status()['counters']['duplicates'], 1)

    def test_collector_transport_exception_preserves_queue(self):
        self.c.sample()
        def crash(c,e):
            raise RuntimeError('interrupted before local commit')
        with self.assertRaises(RuntimeError):
            self.c.flush(send=crash)
        self.assertEqual(self.c.status()['queued'], 1)

    def test_collector_future_schema_rejected(self):
        with self.c.db() as db:
            db.execute("UPDATE metadata SET value='99' WHERE key='schema'")
        with self.assertRaises(CollectorError):
            Collector(self.config)

    def test_collector_invalid_limits(self):
        for args in [{'max_events': 0}, {'max_events': True}, {'max_bytes': 1}, {'max_bytes': 2**40}]:
            with self.assertRaises(CollectorError):
                Collector(self.config, **args)

    def test_collector_http_delivery_and_rotation(self):
        store = Store(self.root/'server.sqlite3')
        admin = store.authenticate(store.identity('lab','operator','admin'))
        token = store.identity('lab','collector','collector')
        collector = store.authenticate(token)
        asset = store.create_asset(admin, {'hostname':'test','os':'test'})
        store.telemetry.create_source(admin, {'name':'endpoint','source_id':'local-test',
                    'collector_id':collector['id'],'asset_ids':[asset['id']]})
        with Server(('127.0.0.1',0), store) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                config = self.config | {'url':f'http://127.0.0.1:{server.server_port}',
                         'asset_id':asset['id'], 'spool':str(self.root/'http.sqlite3')}
                Path(config['token_file']).write_text(token)
                client = Collector(config)
                client.sample()
                self.assertEqual(client.flush(), 1)
                rotated = store.access.change(admin, collector['id'], 'rotate', {'ttl_seconds':300}, collector['version'])
                client.sample()
                self.assertEqual(client.flush(), 0)
                self.assertEqual(client.status()['blocked'], 1)
                Path(config['token_file']).write_text(rotated['token'])
                client.retry_blocked()
                self.assertEqual(client.flush(), 1)
                self.assertEqual(len(store.search(admin,{})['items']), 2)
            finally:
                server.shutdown(); thread.join()

    def test_collector_redirect_never_forwards_key(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/stolen')
                self.end_headers()
            def log_message(self, *_):
                pass
        with ThreadingHTTPServer(('127.0.0.1',0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                self.c.sample()
                status, body, retry = transport(self.config | {'url':f'http://127.0.0.1:{server.server_port}'}, self.queued()[0])
                self.assertEqual(status, 302)
                self.assertEqual(hits, ['/api/v1/events/ingest'])
            finally:
                server.shutdown(); thread.join()

    def test_collector_proxy_environment_ignored(self):
        from urllib.error import URLError
        with patch('bastion.collector.build_opener') as build:
            build.return_value.open.side_effect = URLError('offline')
            self.assertEqual(transport(self.config, {}), (503, {}, None))
            self.assertEqual(build.call_args.args[0].proxies, {})

    def test_collector_cli_sample_and_status(self):
        import subprocess
        import sys
        for command in ['sample', 'status']:
            result = subprocess.run([sys.executable, '-m', 'bastion.collector', '--config',
                                    str(self.config_path), command], capture_output=True, text=True, check=True)
            status = json.loads(result.stdout)
            self.assertEqual(status['queued'], 1)
            self.assertFalse(status['encrypted'])
            self.assertNotIn('fake-key', result.stdout+result.stderr)

    def test_collector_two_flushers_deliver_once(self):
        self.c.sample()
        sent = []
        def send(c,e):
            sent.append(e['event_id'])
            return self.ack(c,e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.c.flush(send=send), range(2)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(sent), 1)
