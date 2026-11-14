"""Optional browser verification: requires playwright and Chromium, not runtime dependencies."""
import json
import argparse
import subprocess
import sys
import os
import threading
from unittest.mock import patch
from pathlib import Path
from playwright.sync_api import sync_playwright
from bastion.core import Store
from bastion.server import Server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', action='store_true')
    args = parser.parse_args()
    credentials = json.loads(next(Path('var').glob('lab-credentials-*.json')).read_text(encoding='utf-8'))
    output = Path('var/ui-check')
    output.mkdir(exist_ok=True)
    with Server(('127.0.0.1', 0), Store('var/bastion.sqlite3')) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            if args.seed:
                subprocess.run([sys.executable, 'tools/demo.py', '--url',
                                f'http://127.0.0.1:{server.server_port}'], check=True)
            # Safe processor fault fixture: no failure injection endpoint exists in the product API.
            principal = server.store.authenticate(credentials['operator']['token'])
            asset = server.store.list(principal, 'assets')[0]
            original = server.store.detect_event
            def controlled_failure(db, row):
                if row['event_id']=='ui-dead':
                    raise ValueError('controlled UI fixture')
                return original(db, row)
            with patch.object(server.store, 'detect_event', side_effect=controlled_failure):
                server.store.ingest(principal, {'events': [{'event_id':'ui-dead', 'source_id':'ui-fault-fixture',
                    'asset_id':asset['id'], 'event_time':'2026-11-14T07:00:00Z', 'schema_version':1,
                    'attributes':{'event_type':'diagnostic'}}]})
                for _ in range(3):
                    server.store.process()
                    with server.store.tx() as db:
                        db.execute("UPDATE events SET next_attempt=0 WHERE event_id='ui-dead'")
            with sync_playwright() as pw:
                options = {'headless': True}
                if os.environ.get('CHROMIUM_EXECUTABLE'):
                    options['executable_path'] = os.environ['CHROMIUM_EXECUTABLE']
                browser = pw.chromium.launch(**options)
                page = browser.new_page(viewport={'width': 1440, 'height': 1000})
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.locator('#token').fill(credentials['operator']['token'])
                page.locator('#login-form button').click()
                page.locator('.stats').wait_for()
                assert page.locator('.number').count() == 4
                page.screenshot(path=str(output/'overview.png'), full_page=True)
                for key in ['alerts', 'assets', 'events', 'rules', 'cases', 'responses', 'audit', 'identities', 'sessions', 'telemetry', 'findings']:
                    page.locator(f'[data-page="{key}"]').click()
                    page.locator('#content .panel').first.wait_for()
                    assert page.locator('#content').inner_text().strip()
                page.locator('[data-page="findings"]').click()
                page.locator('[data-action="import-findings"]').click()
                document=page.locator('#f-document').input_value()
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_role('cell',name='demo-package 1.0',exact=True).wait_for()
                page.locator('[data-action="import-findings"]').click()
                page.locator('#f-document').fill(document)
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                assert page.locator('#content tbody tr').count()==1
                page.locator('[data-action="finding-workflow"]').click()
                page.locator('#f-status').select_option('remediation_planned')
                page.locator('#f-owner').fill('analyst')
                page.locator('#f-due_date').fill('2026-12-01')
                page.locator('#f-reason').fill('Плановое обновление компонента')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('remediation_planned',exact=True).wait_for()
                page.screenshot(path=str(output/'posture.png'),full_page=True)
                page.locator('[data-action="inspect-finding"]').click()
                assert 'manual-import-unverified' in page.locator('#fields pre').inner_text()
                page.locator('#close-modal').click()
                page.locator('[data-page="telemetry"]').click()
                page.locator('[data-action="retry-dead"]').wait_for()
                page.screenshot(path=str(output/'telemetry.png'), full_page=True)
                page.locator('[data-action="retry-dead"]').click()
                page.locator('#f-reason').fill('Controlled fixture removed')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                server.store.process()
                page.locator('#refresh').click()
                page.get_by_text('Ошибок обработки нет', exact=True).wait_for()
                page.locator('[data-action="source-state"]').first.click()
                page.locator('#f-reason').fill('Maintenance test')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('Приостановлен', exact=True).wait_for()
                page.locator('[data-action="source-state"]').first.click()
                page.locator('#f-reason').fill('Maintenance completed')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('Приём включён', exact=True).wait_for()
                page.locator('[data-action="edit-quotas"]').click()
                page.locator('#f-max_events_per_minute').fill('20000')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('20000', exact=True).wait_for()
                page.locator('[data-action="new-source"]').click()
                page.locator('#f-name').fill('UI collector source')
                page.locator('[name="asset"]').first.check()
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_role('cell', name='UI collector source', exact=True).wait_for()
                analyst = server.store.authenticate(credentials['analyst']['token'])
                case = server.store.list(analyst, 'cases')[0]
                alert = next(a for a in server.store.list(analyst, 'alerts') if a['id']==case['alert_id'])
                pending = server.store.response(analyst, {'case_id':case['id'], 'asset_id':alert['asset_id'],
                    'action':'collect_metadata', 'reason':'UI rejection fixture'})
                page.locator('[data-page="responses"]').click()
                page.locator('[data-action="reject-response"]').click()
                page.locator('#f-reason').fill('Недостаточно оснований')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('REJECTED',exact=True).wait_for()
                page.locator('[data-action="cancel-response"]').click()
                page.locator('#f-reason').fill('Согласованная заявка больше не нужна')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_text('CANCELLED',exact=True).wait_for()
                assert page.locator('[data-action="approve"]').count()==0
                page.screenshot(path=str(output/'response-lifecycle.png'), full_page=True)
                page.locator('[data-page="assets"]').click()
                page.locator('[data-action="new-asset"]').click()
                page.locator('#f-hostname').fill('<img src=x onerror=alert(1)>')
                page.locator('#f-os').fill('Synthetic OS')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_role('cell', name='<img src=x onerror=alert(1)>', exact=True).wait_for()
                assert page.locator('#content img').count() == 0
                # Exercise filters and cursor pagination through the real UI.
                server.store.ingest(principal, {'events': [{'event_id':f'page-{i}', 'source_id':'ui-pages',
                    'asset_id':asset['id'], 'event_time':'2026-11-14T08:00:00Z', 'schema_version':1,
                    'attributes':{'event_type':'ui-pagination'}} for i in range(55)]})
                page.locator('[data-page="events"]').click()
                page.locator('[data-action="filter-events"]').click()
                page.locator('#f-event_type').fill('ui-pagination')
                page.locator('#f-source_id').fill('ui-pages')
                page.locator('#f-time_from').fill('2026-11-14T08:00:00Z')
                page.locator('#f-time_to').fill('2026-11-14T08:01:00Z')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.locator('[data-action="more-events"]').wait_for()
                assert page.locator('#content tbody tr').count()==50
                page.locator('[data-action="more-events"]').click()
                page.locator('[data-action="more-events"]').wait_for(state='hidden')
                assert page.locator('#content tbody tr').count()==55
                page.screenshot(path=str(output/'search.png'), full_page=True)
                page.locator('[data-page="rules"]').click()
                page.locator('[data-action="new-rule"]').click()
                page.locator('#f-name').fill('UI composite')
                page.locator('#f-field').select_option('outcome')
                page.locator('#f-value').fill('failure')
                page.locator('#f-field2').select_option('severity')
                page.locator('#f-operator2').select_option('gte')
                page.locator('#f-value2').fill('4')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                row=page.get_by_role('row').filter(has=page.get_by_role('cell',name='UI composite',exact=True))
                row.get_by_role('button',name='Проверить',exact=True).click()
                page.locator('#f-fixtures').fill(json.dumps([
                    {'attributes':{'outcome':'failure','severity':4},'expected':True},
                    {'attributes':{'outcome':'success','severity':4},'expected':False}]))
                page.locator('#submit-modal').click()
                page.get_by_text('Проверка: 2 из 2',exact=True).wait_for()
                page.screenshot(path=str(output/'rule-lab.png'), full_page=True)
                page.locator('#close-modal').click()
                page.locator('[data-page="identities"]').click()
                page.locator('[data-action="new-identity"]').click()
                page.locator('#f-subject').fill('ui-reader')
                page.locator('#f-groups').fill('unrelated-group')
                page.locator('#submit-modal').click()
                page.locator('#issued-key').wait_for()
                reader_key = page.locator('#issued-key').input_value()
                assert len(reader_key) == 43
                page.locator('#close-modal').click()
                page.get_by_role('cell', name='ui-reader', exact=True).wait_for()
                assert page.locator('#issued-key').count() == 0
                page.screenshot(path=str(output/'access.png'), full_page=True)
                reader = browser.new_page()
                reader.goto(f'http://127.0.0.1:{server.server_port}')
                reader.locator('#token').fill(reader_key)
                reader.locator('#login-form button').click()
                reader.locator('.stats').wait_for()
                assert reader.locator('.number').all_text_contents() == ['0','0','0','0']
                assert reader.locator('[data-page="identities"]').count() == 0
                reader.close()
                row = page.get_by_role('row').filter(has=page.get_by_role('cell', name='ui-reader', exact=True))
                row.locator('[data-action="identity-rotate"]').click()
                page.locator('#submit-modal').click()
                page.locator('#issued-key').wait_for()
                assert page.locator('#issued-key').input_value() != reader_key
                page.locator('#close-modal').click()
                row = page.get_by_role('row').filter(has=page.get_by_role('cell', name='ui-reader', exact=True))
                row.locator('[data-action="identity-revoke"]').click()
                page.locator('#f-reason').fill('UI smoke completed')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_role('cell', name='revoked', exact=True).wait_for()
                page.set_viewport_size({'width': 390, 'height': 844})
                page.locator('[data-page="overview"]').click()
                page.locator('.stats').wait_for()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path=str(output/'mobile.png'), full_page=True)
                page.locator('#logout').click()
                page.locator('#login').wait_for(state='visible')
                assert not errors, errors
                browser.close()
                print('UI: 12 sections, source binding/pause/resume, quotas, DLQ retry, filtered cursor, composite fixtures, response reject/cancel, posture import/dedup/plan, access, XSS, 390px — PASS')
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
