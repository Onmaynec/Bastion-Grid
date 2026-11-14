"""Loopback-only HTTP transport for the explicitly selected lab profile."""
import hashlib
import json
import logging
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .core import Problem, Store, exact_fields, require, text_field, uid

log = logging.getLogger('bastion')
WEB = Path(__file__).with_name('web')


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store):
        require(address[0] == '127.0.0.1', message='Lab profile привязывается только к 127.0.0.1')
        self.store = store
        self.stop = threading.Event()
        self.login_attempts = {}
        self.login_lock = threading.Lock()
        super().__init__(address, Handler)
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def work(self):
        while not self.stop.wait(0.5):
            try:
                self.store.process()
            except Exception:
                log.exception('Detection worker failed; transaction rolled back')

    def server_close(self):
        self.stop.set()
        self.worker.join(timeout=12)
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = 'BastionGrid/0.2'

    def log_message(self, *_):
        pass  # No tokens, payloads, or query strings in access logs.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, status, value, headers=None, content_type='application/json; charset=utf-8'):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Request-ID', self.request_id)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        require(self.headers.get('Content-Type', '').split(';')[0] == 'application/json',
                'unsupported_media_type', 'Требуется application/json', 415)
        require(not self.headers.get('Transfer-Encoding'), 'invalid_request')
        length = int(self.headers.get('Content-Length', '0'))
        require(0 < length <= 1048576, 'payload_size', 'Лимит запроса — 1 МиБ', 413)
        raw = self.rfile.read(length)
        require(len(raw) == length, 'invalid_request')
        def unique_pairs(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, 'duplicate_key', 'Повтор ключа JSON')
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
        require(isinstance(value, dict))
        return value

    def principal(self):
        authorization = self.headers.get('Authorization', '')
        if authorization.startswith('Bearer '):
            require(not self.headers.get('Origin'), 'forbidden', 'Bearer разрешён только API-клиентам', 403)
            return self.server.store.authenticate(authorization[7:])
        cookie = SimpleCookie()
        cookie.load(self.headers.get('Cookie', ''))
        require('bg_session' in cookie, 'unauthorized', 'Войдите в стенд', 401)
        token_hash = hashlib.sha256(cookie['bg_session'].value.encode()).hexdigest()
        with self.server.store.connect() as db:
            row = db.execute('SELECT s.csrf,s.id AS session_id,s.expires AS session_expires,i.* FROM sessions s '
                             'JOIN identities i ON i.token_hash=s.identity_hash WHERE s.token_hash=?',
                             (token_hash,)).fetchone()
        require(row is not None and not row['revoked'] and min(row['expires'], row['session_expires']) > time.time(),
                'unauthorized', 'Сеанс истёк или отозван', 401)
        if self.command != 'GET':
            require(secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), row['csrf']),
                    'csrf_failed', 'Требуется CSRF token', 403)
        with self.server.store.tx() as db:
            db.execute('UPDATE sessions SET last_seen=? WHERE id=?', (time.time(), row['session_id']))
        return dict(row)

    def version(self):
        v = self.headers.get('If-Match', '').strip('"')
        require(v.isdecimal(), 'precondition_required', 'Нужен If-Match с текущей версией', 428)
        return int(v)

    def login(self, body):
        exact_fields(body, ['token'], ['token'])
        token = text_field(body, 'token')
        with self.server.login_lock:
            now = time.monotonic()
            attempts = self.server.login_attempts.get(self.client_address[0], [])
            attempts = [x for x in attempts if now-x < 60]
            require(len(attempts) < 20, 'rate_limited', 'Повторите вход через минуту', 429)
            attempts.append(now)
            self.server.login_attempts[self.client_address[0]] = attempts
        p = self.server.store.authenticate(token)
        require(p['role'] != 'collector', 'forbidden', 'Collector не может открыть UI', 403)
        session, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.server.store.tx() as db:
            self.server.store.live_principal(db, p)
            db.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
            db.execute('INSERT INTO sessions(token_hash,identity_hash,csrf,expires,id,created_at,last_seen) '
                       'VALUES(?,?,?,?,?,?,?)',
                       (hashlib.sha256(session.encode()).hexdigest(), p['token_hash'], csrf,
                        min(time.time()+900, p['expires']), uid(), time.time(), time.time()))
            self.server.store.audit(db, p, 'session.created', p['subject'])
        return {'subject': p['subject'], 'role': p['role'], 'tenant': p['tenant'], 'csrf': csrf,
                'policy': json.loads(p['policy']), 'version': p['version']}, {
            'Set-Cookie': f'bg_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900'}

    def dispatch(self):
        self.request_id = uid()
        try:
            host = self.headers.get('Host', '')
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            require(host in allowed, 'invalid_host', 'Неверный Host', 400)
            origin = self.headers.get('Origin')
            if origin:
                require(origin == 'http://'+host, 'origin_denied', 'Запрос другого origin запрещён', 403)
            path = urlsplit(self.path).path
            if self.command == 'GET' and path in {'/', '/app.js', '/style.css'}:
                filename = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[path]
                mime = {'/': 'text/html', '/app.js': 'text/javascript', '/style.css': 'text/css'}[path]
                return self.reply(200, (WEB/filename).read_bytes(), content_type=mime+'; charset=utf-8')
            if self.command == 'GET' and path == '/healthz':
                return self.reply(200, {'status': 'ok', 'version': __version__, 'profile': 'local-lab'})
            body = self.body() if self.command in {'POST', 'PATCH'} else {}
            if path == '/api/v1/session' and self.command == 'POST':
                result, headers = self.login(body)
                return self.reply(200, result, headers)
            p = self.principal()
            s = self.server.store
            if path == '/api/v1/session' and self.command == 'GET':
                return self.reply(200, {'subject': p['subject'], 'role': p['role'], 'tenant': p['tenant'],
                                        'csrf': p.get('csrf'), 'profile': 'local-lab',
                                        'policy': json.loads(p['policy']), 'version': p['version']})
            if path == '/api/v1/logout' and self.command == 'POST':
                require('csrf' in p, 'invalid_request')
                with s.tx() as db:
                    db.execute('DELETE FROM sessions WHERE csrf=? AND identity_hash=?', (p['csrf'], p['token_hash']))
                    s.audit(db, p, 'session.closed', p['subject'])
                return self.reply(200, {'logged_out': True}, {'Set-Cookie': 'bg_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'})
            collections = {'assets', 'rules', 'alerts', 'cases', 'responses', 'evidence', 'audit'}
            parts = path.strip('/').split('/')
            require(parts[:2] == ['api', 'v1'], 'not_found', 'Маршрут не найден', 404)
            tail = parts[2:]
            result = None
            if tail == ['identities'] and self.command == 'GET':
                result = s.access.list_identities(p)
            elif tail == ['identities'] and self.command == 'POST':
                result = s.access.issue(p, body)
            elif len(tail) == 3 and tail[0] == 'identities' and tail[2] in {'rotate', 'revoke', 'policy'} and self.command == 'POST':
                result = s.access.change(p, tail[1], tail[2], body, self.version())
            elif tail == ['sessions'] and self.command == 'GET':
                result = s.access.sessions(p)
            elif len(tail) == 3 and tail[0] == 'sessions' and tail[2] == 'revoke' and self.command == 'POST':
                exact_fields(body, [])
                result = s.access.end_session(p, tail[1])
            elif self.command == 'GET' and len(tail) == 1 and tail[0] in collections:
                result = {'items': s.list(p, tail[0]), 'limit': 500 if tail[0] != 'audit' else None}
            elif self.command == 'GET' and tail == ['evidence', 'export']:
                result = s.export(p)
            elif self.command == 'POST' and tail == ['assets']:
                result = s.create_asset(p, body)
            elif self.command == 'POST' and tail == ['rules']:
                result = s.rule(p, body)
            elif self.command == 'POST' and len(tail) == 3 and tail[0] == 'rules' and tail[2] == 'publish':
                result = s.publish(p, tail[1], self.version())
            elif self.command == 'POST' and len(tail) == 3 and tail[0] == 'rules' and tail[2] == 'replay':
                result = s.replay(p, tail[1])
            elif self.command == 'POST' and tail == ['events', 'ingest']:
                result = s.ingest(p, body)
            elif self.command == 'POST' and tail == ['events', 'search']:
                result = s.search(p, body)
            elif self.command == 'POST' and tail == ['cases']:
                result = s.create_case(p, body, self.headers.get('Idempotency-Key', ''))
            elif self.command == 'PATCH' and len(tail) == 3 and tail[0] == 'cases' and tail[2] == 'status':
                result = s.transition(p, tail[1], body, self.version())
            elif self.command == 'POST' and tail == ['responses']:
                result = s.response(p, body)
            elif self.command == 'POST' and len(tail) == 3 and tail[0] == 'responses' and tail[2] == 'approvals':
                result = s.approve(p, tail[1], self.version())
            elif self.command == 'POST' and tail == ['evidence']:
                result = s.evidence(p, body)
            else:
                raise Problem(404, 'not_found', 'Маршрут не найден')
            headers = {'ETag': f'"{result["version"]}"'} if 'version' in result else {}
            self.reply(200, result, headers)
        except Problem as e:
            self.reply(e.status, {'error_code': e.code, 'message': e.message, 'request_id': self.request_id,
                                  'trace_id': self.request_id, 'version': __version__})
        except (ValueError, TypeError, KeyError, RecursionError):
            self.reply(400, {'error_code': 'invalid_request', 'message': 'Неверный формат запроса',
                             'request_id': self.request_id, 'trace_id': self.request_id, 'version': __version__})
        except Exception:
            log.exception('Request failed: %s', self.request_id)
            self.reply(503, {'error_code': 'service_unavailable', 'message': 'Операция не завершена',
                             'request_id': self.request_id, 'trace_id': self.request_id, 'version': __version__})

    do_GET = dispatch
    do_POST = dispatch
    do_PATCH = dispatch
