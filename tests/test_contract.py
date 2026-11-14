import json
import re
import unittest
from pathlib import Path


class ContractTests(unittest.TestCase):
    def test_contract_routes(self):
        contract = json.loads(Path('spec/openapi.json').read_text(encoding='utf-8'))
        self.assertEqual(contract['openapi'], '3.1.0')
        self.assertEqual(sum(len(ops) for ops in contract['paths'].values()), 29)
        for ops in contract['paths'].values():
            for op in ops.values():
                self.assertIn('200', op['responses'])
                self.assertIn('401', op['responses'])
        for ref in re.findall(r'"\$ref":\s*"#/components/schemas/([^"/]+)"', json.dumps(contract)):
            self.assertIn(ref, contract['components']['schemas'])

    def test_traceability_complete_and_honest(self):
        spec = json.loads(Path('spec/requirements-r2.json').read_text(encoding='utf-8'))
        coverage = json.loads(Path('docs/acceptance/coverage.json').read_text(encoding='utf-8'))
        expected = {r['id'] for section in ['functional_requirements','nonfunctional_requirements'] for r in spec[section]}
        self.assertEqual(len(expected), 619)
        self.assertEqual(expected, {r['id'] for r in coverage['requirements']})
        self.assertFalse(coverage['full_rfp_accepted'])
        tests = '\n'.join(p.read_text(encoding='utf-8') for p in Path('tests').glob('test_*.py'))
        for req in coverage['requirements']:
            for test in req['tests']:
                self.assertIn('def '+test+'(', tests)


if __name__ == '__main__':
    unittest.main()
