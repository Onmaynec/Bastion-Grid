import copy
import unittest
from concurrent.futures import ThreadPoolExecutor
from bastion.core import Problem, Store
from test_core import CoreTests
from test_http import HttpTests


class PostureTests(CoreTests):
    def payload(self, external='scan-1'):
        return {'source':'manual-scanner','observed_at':'2026-11-15T00:00:00Z','findings':[
            {'external_id':external,'asset_id':self.asset['id'],'title':'Synthetic issue','component':'demo',
             'component_version':'1.0','vulnerability_id':'LAB-001','severity':'high'}]}
    def finding(self):
        self.s.posture.ingest(self.admin,self.payload())
        return self.s.posture.list(self.admin)['items'][0]
    def update(self,f,status='investigating',**kwargs):
        return self.s.posture.update(self.admin,f['id'],{'status':status,'owner':'analyst','due_date':None,
            'reason':'test'}|kwargs,f['version'])

    def test_posture_import_atomic_and_idempotent(self):
        body=self.payload();result=self.s.posture.ingest(self.admin,body)
        audit=len(self.s.list(self.admin,'audit'))
        repeat=self.s.posture.ingest(self.admin,body)
        self.assertEqual(repeat['duplicates'],result['created'])
        self.assertEqual(len(self.s.list(self.admin,'audit')),audit)
        body=self.payload('new');body['findings'].append(body['findings'][0]|{'external_id':'bad','asset_id':'missing'})
        with self.assertRaises(Problem):self.s.posture.ingest(self.admin,body)
        self.assertEqual(len(self.s.posture.list(self.admin)['items']),1)

    def test_posture_conflicting_observation_rolls_back(self):
        self.finding();body=self.payload('new');body['findings'].append(self.payload()['findings'][0]|{'severity':'critical'})
        with self.assertRaises(Problem):self.s.posture.ingest(self.admin,body)
        self.assertEqual(len(self.s.posture.list(self.admin)['items']),1)

    def test_posture_batch_duplicate_and_limits(self):
        body=self.payload();body['findings']*=2
        with self.assertRaises(Problem):self.s.posture.ingest(self.admin,body)
        for items in [[],self.payload()['findings']*101]:
            with self.assertRaises(Problem):self.s.posture.ingest(self.admin,self.payload()|{'findings':items})

    def test_posture_validation(self):
        for key,value in [('severity','urgent'),('title',''),('asset_id',[]),('component_version',True)]:
            body=self.payload();body['findings'][0][key]=value
            with self.assertRaises(Problem):self.s.posture.ingest(self.admin,body)
        with self.assertRaises(Problem):self.s.posture.ingest(self.admin,self.payload()|{'observed_at':'2026-11-15'})

    def test_posture_concurrent_repeat_and_restart(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.s.posture.ingest(self.admin,self.payload()),range(2)))
        self.assertEqual(sum(len(r['created']) for r in results),1)
        self.assertEqual(len(Store(self.path).posture.list(self.admin)['items']),1)

    def test_posture_priority_and_provenance(self):
        f=self.finding()
        self.assertEqual(f['priority_score'],45)
        self.assertEqual(f['verification'],'manual-import-unverified')
        self.assertEqual(len(f['observation_sha256']),64)
        self.assertEqual(f['source'],'manual-scanner')

    def test_posture_import_role_and_tenant(self):
        for p in [self.p['analyst'],self.p['auditor'],self.p['other']]:
            with self.assertRaises(Problem):self.s.posture.ingest(p,self.payload())
        self.finding();self.assertEqual(self.s.posture.list(self.p['other'])['items'],[])

    def test_posture_scoped_visibility_and_assignment(self):
        f=self.finding()
        issued=self.s.access.issue(self.admin,{'subject':'limited','role':'analyst','ttl_seconds':300,
            'policy':{'groups':['lab'],'max_sensitivity':'internal','assigned_only':True}})
        p=self.s.authenticate(issued['token'])
        self.assertEqual(self.s.posture.list(p)['items'],[])
        f=self.update(f,owner='limited')
        self.assertEqual(len(self.s.posture.list(p)['items']),1)
        with self.assertRaises(Problem):self.s.posture.update(p,f['id'],{'status':'investigating','owner':'analyst',
            'due_date':None,'reason':'test'},f['version'])

    def test_posture_plan_requires_date_and_owner(self):
        f=self.finding()
        for kwargs in [{},{'due_date':'bad'},{'due_date':'2026-11-31'},{'due_date':'2026-12-01','owner':'missing'}]:
            with self.assertRaises(Problem):self.update(f,'remediation_planned',**kwargs)
        f=self.update(f,'remediation_planned',due_date='2026-12-01')
        self.assertEqual(f['owner'],'analyst')
        self.assertEqual(f['history'][-1]['to'],'remediation_planned')

    def test_posture_stale_and_invalid_transition(self):
        f=self.finding();self.update(f)
        with self.assertRaises(Problem):self.update(f)
        f=self.s.posture.list(self.admin)['items'][0]
        with self.assertRaises(Problem):self.update(f,'fixed')

    def test_posture_fixed_requires_same_asset_evidence(self):
        f=self.update(self.finding(),'remediation_planned',due_date='2026-12-01')
        with self.assertRaises(Problem):self.update(f,'fixed')
        c=self.case();e=self.s.evidence(self.p['analyst'],{'case_id':c['id'],'name':'proof','content':'reviewed result'})
        f=self.update(f,'fixed',evidence_id=e['id'])
        self.assertEqual(f['status'],'fixed')
        self.assertEqual(f['evidence_id'],e['id'])
        f=self.update(f,'investigating');self.assertEqual(f['status'],'investigating')

    def test_posture_terminal_decisions_require_lead(self):
        f=self.finding()
        with self.assertRaises(Problem):self.s.posture.update(self.p['analyst'],f['id'],
            {'status':'accepted','owner':'analyst','due_date':None,'reason':'risk accepted'},f['version'])
        f=self.update(f,'accepted');self.assertEqual(f['status'],'accepted')

    def test_posture_repeat_preserves_workflow(self):
        f=self.update(self.finding(),'accepted')
        self.s.posture.ingest(self.admin,self.payload())
        actual=self.s.posture.list(self.admin)['items'][0]
        self.assertEqual((actual['status'],actual['version']),('accepted',f['version']))

    def test_posture_wrong_asset_evidence_rejected(self):
        f=self.update(self.finding(),'remediation_planned',due_date='2026-12-01')
        self.asset=self.s.create_asset(self.admin,{'hostname':'another','os':'Linux'})
        case=self.case();e=self.s.evidence(self.p['analyst'],{'case_id':case['id'],'name':'proof','content':'different asset'})
        with self.assertRaises(Problem):self.update(f,'fixed',evidence_id=e['id'])

    def test_posture_overdue_and_terminal(self):
        f=self.update(self.finding(),'remediation_planned',due_date='2000-01-01')
        self.assertTrue(self.s.posture.list(self.admin)['items'][0]['overdue'])
        self.update(f,'accepted',due_date='2000-01-01')
        self.assertFalse(self.s.posture.list(self.admin)['items'][0]['overdue'])

    def test_posture_owner_must_have_asset_scope(self):
        f=self.finding()
        self.s.access.issue(self.admin,{'subject':'foreign-group','role':'analyst','ttl_seconds':300,
            'policy':{'groups':['not-lab'],'max_sensitivity':'internal','assigned_only':False}})
        with self.assertRaises(Problem):self.update(f,owner='foreign-group')


class PostureHttpTests(HttpTests):
    def test_posture_http_empty_list_and_rejected_import(self):
        h=self.login()
        status,_,raw=self.request('/api/v1/posture/findings',headers=h)
        self.assertEqual(status,200)
        self.assertEqual(self.request('/api/v1/posture/imports','POST',{},h)[0],400)
        self.assertEqual(self.request('/api/v1/posture/findings')[0],401)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(cls(name) for cls in (PostureTests,PostureHttpTests)
                             for name in cls.__dict__ if name.startswith('test_'))
