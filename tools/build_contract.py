"""Generate the lab OpenAPI contract without external dependencies."""
import json
from pathlib import Path

S = {'type': 'string', 'minLength': 1, 'maxLength': 200}
I = {'type': 'integer'}
def obj(properties, required=()):
    return {'type': 'object', 'additionalProperties': False, 'properties': properties, 'required': list(required)}
def enum(*values):
    return {'type': 'string', 'enum': list(values)}
def ref(name):
    return {'$ref': '#/components/schemas/'+name}

schemas = {
    'Error': obj({k: {'type':'string'} for k in ['error_code','message','request_id','trace_id','version']},
                 ['error_code','message','request_id','trace_id','version']),
    'AssetInput': obj({'hostname': S, 'os': S, 'owner': S, 'group': S,
                       'criticality': {'type':'integer','minimum':1,'maximum':5}}, ['hostname','os']),
    'RuleInput': obj({'name': S, 'field': enum('event_type','outcome','process_name','severity'),
                     'operator': enum('eq','gte','contains'), 'value': {'type':['string','number']},
                     'severity': enum('low','medium','high','critical'), 'technique': {'type':'string','maxLength':40}},
                    ['name','field','operator','value']),
    'Event': obj({'event_id': S, 'source_id': S, 'asset_id': S, 'event_time': {'type':'string','format':'date-time'},
                  'schema_version': {'const':1}, 'attributes': {'type':'object','maxProperties':32}},
                 ['event_id','source_id','asset_id','event_time','schema_version','attributes']),
    'Batch': obj({'events': {'type':'array','minItems':1,'maxItems':100,'items':ref('Event')}}, ['events']),
    'Search': obj({'limit': {'type':'integer','minimum':1,'maximum':100,'default':50},
                   'after': {'type':'integer','minimum':0,'default':0}, 'event_type': S}),
    'CaseInput': obj({'title':S,'owner':S,'alert_id':S}, ['title','owner','alert_id']),
    'Transition': obj({'status': enum('NEW','TRIAGE','INVESTIGATING','CONTAINED','RECOVERING','RESOLVED','CLOSED'),
                       'reason': {'type':'string','minLength':1,'maxLength':2000}}, ['status','reason']),
    'ResponseInput': obj({'asset_id':S,'case_id':S,'action':enum('collect_metadata','isolate_host','release_isolation'),
                          'reason':{'type':'string','minLength':1,'maxLength':2000},
                          'ttl_seconds': {'type':'integer','minimum':30,'maximum':900,'default':300}},
                         ['asset_id','case_id','action','reason']),
    'EvidenceInput': obj({'case_id':S,'name':S,'content':{'type':'string','minLength':1,'maxLength':65536}},
                         ['case_id','name','content']),
    'SessionInput': obj({'token':S}, ['token']),
    'Empty': obj({}),
    'Resource': {'type':'object','required':['id','tenant_id','version','created_at','created_by'],
                 'properties': {'id':{'type':'string','format':'uuid'},'tenant_id':S,'version':{'type':'integer','minimum':1},
                                'created_at':{'type':'string','format':'date-time'},'created_by':S},
                 'additionalProperties':True},
    'Collection': {'type':'object','required':['items','limit'],'properties':{'items':{'type':'array','items':{'type':'object'}},
                                                                             'limit':{'type':['integer','null']}}},
    'Ack': obj({'accepted':{'type':'array','items':I},'duplicates':{'type':'array','items':I},
                'durable':{'const':True},'detection_complete':{'const':False}},
               ['accepted','duplicates','durable','detection_complete']),
    'SearchResult': obj({'items':{'type':'array','items':{'type':'object'}},'next_cursor':{'type':['integer','null']},
                         'order':{'const':'ingest_sequence'}}, ['items','next_cursor','order']),
    'Replay': obj({'rule_id':S,'rule_version':I,'matched_sequences':{'type':'array','items':I},'scanned':I,
                   'dry_run':{'const':True}}, ['rule_id','rule_version','matched_sequences','scanned','dry_run']),
    'Bundle': {'type':'object','required':['format','tenant_id','evidence','audit','checkpoint','signature','trust'],
               'properties': {'format':{'const':'bastion-evidence-v1'},'tenant_id':S,'evidence':{'type':'array','items':ref('Resource')},
                              'audit':{'type':'array','items':{'type':'object'}},'checkpoint':S,'signature':{'type':'null'},
                              'trust':{'const':'unanchored-local-hash-chain'}}},
    'Session': {'type':'object','required':['subject','role','tenant','csrf'],
                'properties':{'subject':S,'role':S,'tenant':S,'csrf':{'type':['string','null']},'profile':S}},
    'Logout': obj({'logged_out':{'const':True}}, ['logged_out']),
}
paths={}
def endpoint(path,method,summary,request=None,response='Resource',version=False,key=False,anonymous=False):
    op={'operationId':method+'_'+path.replace('/','_').replace('{','').replace('}',''), 'summary':summary,
        'responses':{'200':{'description':'Операция завершена','content':{'application/json':{'schema':ref(response)}}},
                     **{str(code):{'description':msg,'content':{'application/json':{'schema':ref('Error')}}}
                        for code,msg in [(400,'Неверный запрос'),(401,'Нет действующей сессии'),(403,'Доступ запрещён'),
                                         (404,'Объект не найден'),(409,'Конфликт'),(413,'Слишком большой запрос'),
                                         (415,'Неверный Content-Type'),(422,'Нарушение политики'),(428,'Нет If-Match'),
                                         (429,'Rate limit'),(503,'Сервис недоступен')]}},
        'security':[] if anonymous else [{'bearerAuth':[]},{'sessionCookie':[]}]}
    params=[]
    if '{id}' in path:
        params.append({'name':'id','in':'path','required':True,'schema':S})
    if version:
        params.append({'name':'If-Match','in':'header','required':True,'schema':{'type':'string','example':'"1"'}})
    if key:
        params.append({'name':'Idempotency-Key','in':'header','required':True,'schema':{'type':'string','maxLength':128}})
    if method!='get' and not anonymous:
        params.append({'name':'X-CSRF-Token','in':'header','required':False,'schema':S,
                       'description':'Обязателен при cookie session. Bearer принимается только без Origin.'})
    if params: op['parameters']=params
    if request: op['requestBody']={'required':True,'content':{'application/json':{'schema':ref(request)}}}
    paths.setdefault('/api/v1/'+path,{})[method]=op

for collection in ['assets','rules','alerts','cases','responses','evidence','audit']:
    endpoint(collection,'get','Список '+collection,response='Collection')
for path,request in [('assets','AssetInput'),('rules','RuleInput'),('cases','CaseInput'),('responses','ResponseInput'),('evidence','EvidenceInput')]:
    endpoint(path,'post','Создание '+path,request,key=path=='cases')
endpoint('events/ingest','post','Durable ACK локального хранилища','Batch','Ack')
endpoint('events/search','post','Курсор по порядку приёма','Search','SearchResult')
endpoint('rules/{id}/publish','post','Независимая публикация','Empty',version=True)
endpoint('rules/{id}/replay','post','Replay до 10 000 событий без алертов','Empty','Replay')
endpoint('cases/{id}/status','patch','Переход состояния кейса','Transition',version=True)
endpoint('responses/{id}/approvals','post','Независимый голос согласования','Empty',version=True)
endpoint('evidence/export','get','Экспорт без цифровой подписи',response='Bundle')
endpoint('session','post','Лабораторный вход','SessionInput','Session',anonymous=True)
endpoint('session','get','Текущий сеанс',response='Session')
endpoint('logout','post','Завершить текущий сеанс','Empty','Logout')
contract={'openapi':'3.1.0','info':{'title':'BASTION GRID local lab API','version':'0.1.0',
 'description':'Контракт реализованного лабораторного подмножества. Отличия маршрутов от целевого RFP — ADR-004. Не production API.'},
 'servers':[{'url':'http://127.0.0.1:8080'}], 'paths':paths,
 'components':{'schemas':schemas,'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer'},
              'sessionCookie':{'type':'apiKey','in':'cookie','name':'bg_session'}}}}
if __name__=='__main__':
    Path('spec/openapi.json').write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n', encoding='utf-8', newline='\n')
