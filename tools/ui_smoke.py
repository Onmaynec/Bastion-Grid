"""Optional browser verification: requires playwright and Chromium, not runtime dependencies."""
import json
import argparse
import subprocess
import sys
import os
import threading
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
                for key in ['alerts', 'assets', 'events', 'rules', 'cases', 'responses', 'audit']:
                    page.locator(f'[data-page="{key}"]').click()
                    page.locator('#content .panel').wait_for()
                    assert page.locator('#content').inner_text().strip()
                page.locator('[data-page="assets"]').click()
                page.locator('[data-action="new-asset"]').click()
                page.locator('#f-hostname').fill('<img src=x onerror=alert(1)>')
                page.locator('#f-os').fill('Synthetic OS')
                page.locator('#submit-modal').click()
                page.locator('#modal').wait_for(state='hidden')
                page.get_by_role('cell', name='<img src=x onerror=alert(1)>', exact=True).wait_for()
                assert page.locator('#content img').count() == 0
                page.set_viewport_size({'width': 390, 'height': 844})
                page.locator('[data-page="overview"]').click()
                page.locator('.stats').wait_for()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path=str(output/'mobile.png'), full_page=True)
                page.locator('#logout').click()
                page.locator('#login').wait_for(state='visible')
                assert not errors, errors
                browser.close()
                print('UI: 8 sections, create form, escaped XSS, 390px layout, logout — PASS')
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
