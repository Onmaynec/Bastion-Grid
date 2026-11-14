import json
import unittest
from bastion.core import Problem
from test_core import CoreTests
from test_http import HttpTests


class AnalyticsTests(CoreTests):
    def composite(self, match='all'):
        return self.s.rule(self.admin, {'name':'Two conditions','match':match,'conditions':[
            {'field':'outcome','operator':'eq','value':'failure'},
            {'field':'severity','operator':'gte','value':4}]})

    def test_composite_all_any(self):
        for mode in ['all','any']:
            rule = self.composite(mode)
            self.assertTrue(self.s.matches(rule,self.event()))
            self.assertEqual(self.s.matches(rule, {'attributes':{'outcome':'failure'}}), mode=='any')
            self.assertFalse(self.s.matches(rule, {'attributes':{}}))

    def test_composite_validation(self):
        base={'name':'bad','conditions':[]}
        for body in [base,base|{'conditions':[{}]},base|{'conditions':[{'field':[],'operator':'eq','value':1}]},
                     base|{'conditions':[{'field':'severity','operator':'gte','value':True}]},
                     base|{'conditions':[{'field':'severity','operator':'eq','value':float('nan')}]},
                     base|{'conditions':[{'field':'severity','operator':'eq','value':1}]*9},
                     base|{'conditions':[{'field':'severity','operator':'eq','value':1}], 'field':'severity'}]:
            with self.assertRaises(Problem): self.s.rule(self.admin,body)

    def test_composite_live_replay_and_explanation(self):
        rule=self.composite();self.s.publish(self.p['lead1'],rule['id'],rule['version'])
        self.s.ingest(self.admin,{'events':[self.event(),self.event(2)|{'attributes':{'outcome':'success','severity':9}}]})
        replay=self.s.replay(self.admin,rule['id'])
        self.assertEqual(len(replay['matched_sequences']),1)
        self.s.process()
        alerts=self.s.list(self.admin,'alerts');self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]['event_seq'],replay['matched_sequences'][0])
        self.assertEqual(alerts[0]['explanation']['results'],[True,True])
        self.s.process();self.assertEqual(len(self.s.list(self.admin,'alerts')),1)

    def test_fixtures_no_side_effects_and_failed_expectation(self):
        rule=self.composite()
        audit=len(self.s.list(self.admin,'audit'))
        result=self.s.test_rule(self.admin,rule['id'],{'fixtures':[
            {'attributes':self.event()['attributes'],'expected':True}, {'attributes':{},'expected':True}]})
        self.assertEqual((result['passed'],result['total']),(1,2))
        self.assertEqual(result['results'][1]['conditions'],[False,False])
        self.assertEqual(self.s.list(self.admin,'alerts'),[])
        self.assertEqual(len(self.s.list(self.admin,'audit')),audit)

    def test_fixtures_strict_limits(self):
        rule=self.composite()
        for fixtures in [[],[{'attributes':{},'expected':1}], [{'attributes':{},'expected':False}]*101,
                         [{'attributes':{'x':'x'*65536},'expected':False}]]:
            with self.assertRaises(Problem): self.s.test_rule(self.admin,rule['id'],{'fixtures':fixtures})

    def test_fixture_tenant_and_scoped_denial(self):
        rule=self.composite();body={'fixtures':[{'attributes':{},'expected':False}]}
        with self.assertRaises(Problem):self.s.test_rule(self.p['other'],rule['id'],body)
        issued=self.s.access.issue(self.admin,{'subject':'scoped','role':'analyst','ttl_seconds':300,
            'policy':{'groups':['lab'],'max_sensitivity':'internal','assigned_only':False}})
        with self.assertRaises(Problem):self.s.test_rule(self.s.authenticate(issued['token']),rule['id'],body)

    def test_search_combined_filters(self):
        self.s.ingest(self.admin,{'events':[self.event(),self.event(2)|{'source_id':'s2'}]})
        query={'source_id':'s1','asset_id':self.asset['id'],'outcome':'failure','event_type':'authentication'}
        self.assertEqual(len(self.s.search(self.admin,query)['items']),1)
        self.assertEqual(self.s.search(self.admin,query|{'outcome':'success'})['items'],[])
        self.assertEqual(self.s.search(self.p['other'],query)['items'],[])

    def test_search_half_open_timezone_range(self):
        self.s.ingest(self.admin,{'events':[self.event(),self.event(2)|{'event_time':'2026-11-14T07:01:00Z'}]})
        result=self.s.search(self.admin,{'time_from':'2026-11-14T10:00:00+03:00','time_to':'2026-11-14T07:01:00Z'})
        self.assertEqual([x['event_id'] for x in result['items']],['e1'])

    def test_search_bad_ranges(self):
        for query in [{'time_from':'bad'},{'time_to':'2026-11-14'},
                      {'time_from':'2026-11-15T00:00:00Z','time_to':'2026-11-14T00:00:00Z'},
                      {'time_from':True},{'outcome':[]},{'source_id':"' OR 1=1 --"}]:
            if isinstance(query.get('source_id'),str):
                self.assertEqual(self.s.search(self.admin,query)['items'],[])
            else:
                with self.assertRaises(Problem):self.s.search(self.admin,query)

    def test_filtered_cursor_has_no_duplicates(self):
        self.s.ingest(self.admin,{'events':[self.event(i) for i in range(7)]})
        found=[];after=0
        while True:
            result=self.s.search(self.admin,{'source_id':'s1','limit':2,'after':after})
            found.extend(x['event_id'] for x in result['items'])
            after=result['next_cursor']
            if after is None:break
        self.assertEqual(found,[f'e{i}' for i in range(7)])

    def test_legacy_fixture_compatible(self):
        rule=self.rule()
        result=self.s.test_rule(self.admin,rule['id'],{'fixtures':[{'attributes':self.event()['attributes'],'expected':True}]})
        self.assertEqual(result['passed'],1)


class AnalyticsHttpTests(HttpTests):
    def test_rule_fixture_http(self):
        h=self.login()
        status,_,raw=self.request('/api/v1/rules','POST',{'name':'http','conditions':[{'field':'outcome','operator':'eq','value':'failure'}]},h)
        self.assertEqual(status,200)
        rule=json.loads(raw)
        status,_,raw=self.request('/api/v1/rules/'+rule['id']+'/test','POST',{'fixtures':[{'attributes':{'outcome':'failure'},'expected':True}]},h)
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['passed'],1)
        self.assertEqual(self.request('/api/v1/rules/'+rule['id']+'/test','POST',{'fixtures':[]})[0],401)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cls(name) for cls in (AnalyticsTests,AnalyticsHttpTests)
                              for name in cls.__dict__ if name.startswith('test_'))
