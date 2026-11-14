import argparse
from contextlib import closing
import json
import os
import sqlite3
from pathlib import Path

from .core import Store, verify, Problem


def main():
    parser = argparse.ArgumentParser(description='BASTION GRID local engineering lab')
    parser.add_argument('--db', default='var/bastion.sqlite3')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='Создать лабораторные учётные записи')
    init.add_argument('--tenant', default='northstar-lab')
    serve = sub.add_parser('serve', help='Запустить только локальный стенд')
    serve.add_argument('--lab', action='store_true', required=True)
    serve.add_argument('--port', type=int, default=8080)
    verify_cmd = sub.add_parser('verify', help='Независимая проверка экспорта')
    verify_cmd.add_argument('bundle')
    verify_cmd.add_argument('--checkpoint')
    backup = sub.add_parser('backup', help='Согласованный SQLite backup')
    backup.add_argument('destination')
    revoke = sub.add_parser('revoke', help='Отозвать лабораторную учётную запись')
    revoke.add_argument('tenant')
    revoke.add_argument('subject')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'verify':
        try:
            result = verify(json.loads(Path(args.bundle).read_text(encoding='utf-8')), args.checkpoint)
        except (Problem, OSError, ValueError, RecursionError) as error:
            print(json.dumps({'valid': False, 'error_code': error.code if isinstance(error, Problem) else 'invalid_bundle'}))
            raise SystemExit(1) from None
        print(json.dumps(result, indent=2))
        return
    store = Store(args.db)
    if store.migration_backup:
        print(f'Перед миграцией сохранён snapshot: {store.migration_backup}')
    if args.command == 'init':
        with store.connect() as db:
            if db.execute('SELECT 1 FROM identities WHERE tenant=?', (args.tenant,)).fetchone():
                parser.error('Тенант уже инициализирован; существующие ключи не изменены')
        credentials = {}
        for subject, role in [('operator', 'admin'), ('analyst', 'analyst'), ('reviewer-one', 'lead'),
                              ('reviewer-two', 'lead'), ('auditor', 'auditor'), ('collector', 'collector')]:
            credentials[subject] = {'role': role, 'token': store.identity(args.tenant, subject, role)}
        output = Path(args.db).parent / f'lab-credentials-{__import__("hashlib").sha256(args.tenant.encode()).hexdigest()[:12]}.json'
        output.write_text(json.dumps(credentials, indent=2), encoding='utf-8', newline='\n')
        output.chmod(0o600)
        print(f'Ключи на 24 часа: {output}. Вход в UI — ключ operator. Это не production identity.')
    elif args.command == 'serve':
        from .server import Server
        with Server(('127.0.0.1', args.port), store) as server:
            print(f'BASTION GRID • local lab • http://127.0.0.1:{server.server_port}', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    elif args.command == 'backup':
        destination = Path(args.destination)
        if destination.exists():
            parser.error('Файл назначения уже существует')
        with store.connect() as source, closing(sqlite3.connect(destination)) as target:
            source.backup(target)
        print(f'Снимок создан: {destination}')
    elif args.command == 'revoke':
        with store.tx() as db:
            db.execute('DELETE FROM sessions WHERE identity_hash IN (SELECT token_hash FROM identities '
                       'WHERE tenant=? AND subject=?)', (args.tenant, args.subject))
            changed = db.execute('UPDATE identities SET revoked=1,version=version+1 WHERE tenant=? AND subject=?',
                                 (args.tenant, args.subject)).rowcount
            store.audit(db, {'tenant': args.tenant, 'subject': 'local-administrator'},
                        'identity.revoked', args.subject, {'changed': changed})
        print(f'Отозвано учётных записей: {changed}')


if __name__ == '__main__':
    main()
