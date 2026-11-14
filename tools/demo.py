"""Create deterministic synthetic observations through the real HTTP API."""
import argparse
import json
import time
import uuid
from pathlib import Path
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--credentials')
    args = parser.parse_args()
    path = Path(args.credentials) if args.credentials else next(Path('var').glob('lab-credentials-*.json'))
    credentials = json.loads(path.read_text(encoding='utf-8'))
    def call(who, route, method='GET', body=None, headers=None):
        request = Request(args.url+'/api/v1/'+route, method=method,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers={'Content-Type': 'application/json',
                                   'Authorization': 'Bearer '+credentials[who]['token']} | (headers or {}))
        with urlopen(request, timeout=10) as response:
            return json.load(response)
    assets = []
    for name, os_name, criticality in [('SOC-WIN-023', 'Windows 11', 4), ('APP-LNX-007', 'Ubuntu 24.04', 5),
                                       ('EDGE-LNX-012', 'Debian 12', 3), ('LAB-WIN-004', 'Windows 11', 2)]:
        assets.append(call('operator', 'assets', 'POST', {'hostname': name, 'os': os_name,
                           'owner': 'SOC / Lab', 'criticality': criticality}))
    rule = call('operator', 'rules', 'POST', {'name': 'Неуспешная аутентификация', 'field': 'outcome',
               'operator': 'eq', 'value': 'failure', 'severity': 'high', 'technique': 'T1110'})
    call('reviewer-one', f'rules/{rule["id"]}/publish', 'POST', {}, {'If-Match': str(rule['version'])})
    run = str(uuid.uuid4())
    collector = next(i for i in call('operator', 'identities')['items'] if i['subject']=='collector')
    source_id = 'synthetic-'+run
    source = call('operator', 'telemetry/sources', 'POST', {'name': 'Synthetic fixture', 'source_id': source_id,
                  'collector_id': collector['id'], 'asset_ids': [a['id'] for a in assets]})
    events = [{'event_id': f'{run}-{i}', 'source_id': source_id, 'asset_id': assets[i%4]['id'],
               'event_time': f'2026-11-14T07:{i:02d}:00Z', 'schema_version': 1,
               'attributes': {'event_type': 'authentication', 'outcome': 'failure' if i%3==0 else 'success',
                              'process_name': 'lab-fixture', 'severity': 4 if i%3==0 else 1}}
              for i in range(12)]
    ack = call('collector', 'events/ingest', 'POST', {'events': events})
    replay = call('collector', 'events/ingest', 'POST', {'events': events})
    assert len(ack['accepted']) == 12 and len(replay['duplicates']) == 12
    deadline = time.monotonic()+10
    alerts = []
    while time.monotonic() < deadline:
        alerts = [a for a in call('analyst', 'alerts')['items'] if a['rule_id'] == rule['id']]
        if len(alerts) == 4:
            break
        time.sleep(.1)
    assert len(alerts) == 4, 'Detection did not complete'
    case = call('analyst', 'cases', 'POST', {'title': 'Проверка синтетических входов',
                'owner': 'analyst', 'alert_id': alerts[0]['id']}, {'Idempotency-Key': run})
    case = call('analyst', f'cases/{case["id"]}/status', 'PATCH', {'status': 'TRIAGE',
                'reason': 'Контрольный сценарий; источник подтверждён'}, {'If-Match': str(case['version'])})
    call('analyst', 'evidence', 'POST', {'case_id': case['id'], 'name': 'synthetic-observation.txt',
         'content': 'Тестовый артефакт. Реальных пользовательских данных нет.\nRun: '+run})
    job = call('analyst', 'responses', 'POST', {'case_id': case['id'], 'asset_id': alerts[0]['asset_id'],
               'action': 'collect_metadata', 'reason': 'Синтетическая проверка согласования'})
    job = call('reviewer-one', f'responses/{job["id"]}/approvals', 'POST', {}, {'If-Match': str(job['version'])})
    job = call('reviewer-two', f'responses/{job["id"]}/approvals', 'POST', {}, {'If-Match': str(job['version'])})
    assert job['status'] == 'APPROVED' and job['simulation_only']
    health = call('auditor', 'telemetry/health')
    source_stats = next(x for x in call('operator', 'telemetry/sources')['items'] if x['id']==source['id'])
    assert source_stats['accepted_count']==12 and source_stats['duplicate_count']==12
    assert health['counts']['done'] >= 12
    bundle = call('auditor', 'evidence/export')
    output = Path('var/demo-evidence.json')
    output.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    print(json.dumps({'accepted': 12, 'duplicates': 12, 'alerts': 4, 'case': case['id'],
                      'response': job['status'], 'execution': False, 'bundle': str(output)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
