import copy
import json
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from bastion.core import Problem, verify, Store
from test_core import CoreTests
from test_http import HttpTests


class LifecycleTests(CoreTests):
    def test_reject_records_reason_and_blocks_approval(self):
        job=self.job()
        result=self.s.finish_response(self.p['lead1'],job['id'],'reject',{'reason':'Не подтверждён scope'},job['version'])
        self.assertEqual(result['status'],'REJECTED')
        self.assertEqual(result['resolution']['actor'],'lead1')
        self.assertTrue(result['simulation_only'])
        with self.assertRaises(Problem):self.s.approve(self.p['lead2'],job['id'],result['version'])

    def test_requester_can_cancel_approved(self):
        job=self.job()
        for who in ('lead1','lead2'):job=self.s.approve(self.p[who],job['id'],job['version'])
        job=self.s.finish_response(self.p['analyst'],job['id'],'cancel',{'reason':'Больше не требуется'},job['version'])
        self.assertEqual(job['status'],'CANCELLED');self.assertEqual(len(job['approvals']),2)
        with self.assertRaises(Problem):self.s.finish_response(self.admin,job['id'],'cancel',{'reason':'again'},job['version'])

    def test_cancel_reject_scope_and_roles(self):
        job=self.job()
        other=self.s.authenticate(self.s.identity('a','another-analyst','analyst'))
        for p,op in [(other,'cancel'),(self.p['analyst'],'reject'),(self.p['auditor'],'cancel'),(self.p['other'],'cancel')]:
            with self.assertRaises(Problem):self.s.finish_response(p,job['id'],op,{'reason':'test'},job['version'])
        self.assertEqual(self.s.list(self.admin,'responses')[0]['version'],job['version'])

    def test_finish_requires_version_reason_and_unexpired(self):
        job=self.job()
        for body,version in [({'reason':''},job['version']),({'reason':'test','extra':1},job['version']),({'reason':'test'},99)]:
            with self.assertRaises(Problem):self.s.finish_response(self.admin,job['id'],'cancel',body,version)
        with patch('bastion.core.time.time',return_value=job['expires_at']):
            with self.assertRaises(Problem):self.s.finish_response(self.admin,job['id'],'cancel',{'reason':'test'},job['version'])

    def test_expiry_persists_once_and_preserves_terminal(self):
        first=self.job();second=self.job();third=self.job()
        for who in ('lead1','lead2'):second=self.s.approve(self.p[who],second['id'],second['version'])
        third=self.s.finish_response(self.admin,third['id'],'cancel',{'reason':'test'},third['version'])
        with patch('bastion.core.time.time',return_value=max(first['expires_at'],second['expires_at'],third['expires_at'])+1):
            self.assertEqual(self.s.expire_responses(),2)
            self.assertEqual(self.s.expire_responses(),0)
        restored=Store(self.path).list(self.admin,'responses')
        self.assertEqual(sorted(x['status'] for x in restored),['CANCELLED','EXPIRED','EXPIRED'])
        expired=[a for a in self.s.list(self.admin,'audit') if a['body']['action']=='response.expired']
        self.assertEqual(len(expired),2)

    def test_expiry_bounded_and_concurrent(self):
        jobs=[self.job() for _ in range(3)]
        with patch('bastion.core.time.time',return_value=max(j['expires_at'] for j in jobs)+1):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(lambda _:self.s.expire_responses(1),range(2)))
            self.assertEqual(sum(results),2)
            self.assertEqual(self.s.expire_responses(),1)

    def test_approval_cancel_race_version(self):
        job=self.job()
        def run(op):
            try:
                if op=='approve':self.s.approve(self.p['lead1'],job['id'],job['version'])
                else:self.s.finish_response(self.p['analyst'],job['id'],'cancel',{'reason':'test'},job['version'])
                return True
            except Problem:return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(run,['approve','cancel'])),1)

    def test_verifier_malformed_inputs_fail_cleanly(self):
        for bundle in [None,[],{}, {'format':'bastion-evidence-v1'}, {'format':'bastion-evidence-v1','tenant_id':'a','audit':None,'evidence':[]}]:
            with self.assertRaises(Problem):verify(bundle)

    def test_verifier_bad_base64_and_size(self):
        bundle=self.bundle()
        for field,value in [('content_base64','???'),('content_base64',None),('size',True),('sha256','Ж'*64),('id',[])]:
            bad=copy.deepcopy(bundle);bad['evidence'][0][field]=value
            with self.assertRaises(Problem):verify(bad)

    def test_verifier_sequence_and_duplicate_evidence(self):
        bundle=self.bundle()
        for value in [0,True,'1']:
            bad=copy.deepcopy(bundle);bad['audit'][0]['seq']=value
            with self.assertRaises(Problem):verify(bad)
        bad=copy.deepcopy(bundle);bad['audit'][1]['seq']=bad['audit'][0]['seq']
        with self.assertRaises(Problem):verify(bad)
        bundle['evidence'].append(copy.deepcopy(bundle['evidence'][0]))
        with self.assertRaises(Problem):verify(bundle)

    def test_verifier_explicit_checkpoint_required_valid(self):
        bundle=self.bundle()
        for checkpoint in ['',False,'x'*64,'0'*64]:
            with self.assertRaises(Problem):verify(bundle,checkpoint)
        self.assertTrue(verify(bundle,bundle['checkpoint'])['anchored'])

    def test_verifier_rejects_claimed_signature(self):
        bundle=self.bundle();bundle['signature']='pretend-signed'
        with self.assertRaises(Problem):verify(bundle)

    def test_verifier_cli_invalid_has_no_traceback(self):
        path=Path(self.tmp.name)/'bad.json';path.write_text('{"format":"bastion-evidence-v1"}')
        result=subprocess.run([sys.executable,'-m','bastion','verify',str(path)],capture_output=True,text=True)
        self.assertEqual(result.returncode,1)
        self.assertFalse(json.loads(result.stdout)['valid'])
        self.assertNotIn('Traceback',result.stderr)


class LifecycleHttpTests(HttpTests):
    def test_response_cancel_http(self):
        p=self.s.authenticate(self.token)
        asset=self.s.create_asset(p,{'hostname':'test','os':'Linux'})
        rule=self.s.rule(p,{'name':'test','field':'outcome','operator':'eq','value':'failure'})
        lead=self.s.authenticate(self.s.identity('a','lead','lead'))
        self.s.publish(lead,rule['id'],rule['version'])
        self.s.ingest(p,{'events':[{'event_id':'1','source_id':'s','asset_id':asset['id'],
            'event_time':'2026-11-14T00:00:00Z','schema_version':1,'attributes':{'outcome':'failure'}}]})
        self.s.process();alert=self.s.list(p,'alerts')[0]
        case=self.s.create_case(p,{'title':'test','owner':'admin','alert_id':alert['id']},'test')
        job=self.s.response(p,{'case_id':case['id'],'asset_id':asset['id'],'action':'collect_metadata','reason':'test'})
        h=self.login()|{'If-Match':str(job['version'])}
        status,_,raw=self.request('/api/v1/responses/'+job['id']+'/cancel','POST',{'reason':'cancel test'},h)
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['status'],'CANCELLED')


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (LifecycleTests,LifecycleHttpTests)
                              for name in cls.__dict__ if name.startswith('test_'))
