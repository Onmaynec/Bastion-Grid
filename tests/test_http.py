import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from bastion.core import Store
from bastion.server import Server


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name)/'db.sqlite')
        self.token = self.s.identity('a', 'admin', 'admin')
        self.server = Server(('127.0.0.1', 0), self.s)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, path, method='GET', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        raw = json.dumps(body) if body is not None else None
        h = {'Content-Type': 'application/json'} | (headers or {})
        conn.request(method, path, body=raw, headers=h)
        response = conn.getresponse()
        data = response.read()
        result = response.status, dict(response.getheaders()), data
        conn.close()
        return result

    def login(self):
        status, headers, raw = self.request('/api/v1/session', 'POST', {'token': self.token})
        self.assertEqual(status, 200)
        return {'Cookie': headers['Set-Cookie'].split(';')[0], 'X-CSRF-Token': json.loads(raw)['csrf']}

    def test_requires_auth(self):
        self.assertEqual(self.request('/api/v1/assets')[0], 401)

    def test_cookie_security_and_csp(self):
        status, headers, _ = self.request('/api/v1/session', 'POST', {'token': self.token})
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_csrf(self):
        h = self.login()
        del h['X-CSRF-Token']
        self.assertEqual(self.request('/api/v1/assets', 'POST', {'hostname': 'x', 'os': 'Linux'}, h)[0], 403)

    def test_cross_origin_and_host(self):
        self.assertEqual(self.request('/healthz', headers={'Host': 'evil.example'})[0], 400)
        self.assertEqual(self.request('/api/v1/session', 'POST', {'token': self.token}, {'Origin': 'https://evil.example'})[0], 403)

    def test_logout_invalidates_session(self):
        h = self.login()
        self.assertEqual(self.request('/api/v1/logout', 'POST', {}, h)[0], 200)
        self.assertEqual(self.request('/api/v1/assets', headers=h)[0], 401)

    def test_revocation_invalidates_cookie(self):
        h = self.login()
        with self.s.tx() as db:
            db.execute('UPDATE identities SET revoked=1')
        self.assertEqual(self.request('/api/v1/assets', headers=h)[0], 401)

    def test_collector_no_ui(self):
        token = self.s.identity('a', 'collector', 'collector')
        self.assertEqual(self.request('/api/v1/session', 'POST', {'token': token})[0], 403)

    def test_http_create_and_tenant_spoof(self):
        h = self.login()
        self.assertEqual(self.request('/api/v1/assets', 'POST', {'hostname': 'x', 'os': 'Linux'}, h)[0], 200)
        self.assertEqual(self.request('/api/v1/assets', 'POST', {'hostname': 'x', 'os': 'Linux', 'tenant_id': 'b'}, h)[0], 400)
        self.assertEqual(len(json.loads(self.request('/api/v1/assets', headers=h)[2])['items']), 1)

    def test_error_contract_and_no_stacktrace(self):
        status, _, raw = self.request('/api/v1/assets')
        body = json.loads(raw)
        self.assertTrue({'error_code', 'message', 'request_id', 'trace_id', 'version'} <= body.keys())
        self.assertNotIn('Traceback', raw.decode())

    def test_lab_not_public(self):
        with self.assertRaises(Exception):
            Server(('0.0.0.0', 0), self.s)

    def test_unknown_route_and_static_traversal(self):
        h = self.login()
        self.assertEqual(self.request('/api/v1/run-shell', 'POST', {}, h)[0], 404)
        self.assertEqual(self.request('/../core.py', headers=h)[0], 404)

    def test_missing_version(self):
        h = self.login()
        self.assertEqual(self.request('/api/v1/cases/anything/status', 'PATCH', {'status': 'TRIAGE'}, h)[0], 428)


if __name__ == '__main__':
    unittest.main()
