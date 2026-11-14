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
                       'sensitivity': enum('public','internal','confidential','restricted'),
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
schemas.update({
    'AccessPolicy': obj({'groups': {'type':'array','minItems':1,'maxItems':50,'uniqueItems':True,
                                   'items':{'type':'string','minLength':1,'maxLength':100}},
                         'max_sensitivity': enum('public','internal','confidential','restricted'),
                         'assigned_only': {'type':'boolean'}}, ['groups','max_sensitivity','assigned_only']),
    'IdentityInput': obj({'subject': {'type':'string','minLength':1,'maxLength':100},
                         'role':enum('admin','analyst','lead','auditor','collector'),
                         'ttl_seconds':{'type':'integer','minimum':60,'maximum':86400},
                         'policy':ref('AccessPolicy')}, ['subject','role','ttl_seconds','policy']),
    'Identity': {'type':'object','required':['id','subject','role','expires','revoked','version','policy','status'],
                 'properties':{'id':S,'subject':S,'role':S,'expires':{'type':'number'},'revoked':{'type':'integer'},
                               'version':I,'policy':ref('AccessPolicy'),'status':enum('active','revoked','expired'),
                               'token':{'type':'string','description':'Показывается один раз при issue/rotate'},
                               'token_display':{'const':'once'}}},
    'RotateIdentity': obj({'ttl_seconds':{'type':'integer','minimum':60,'maximum':86400}}, ['ttl_seconds']),
    'RevokeIdentity': obj({'reason':{'type':'string','minLength':1,'maxLength':1000}}, ['reason']),
    'ChangePolicy': obj({'policy':ref('AccessPolicy')}, ['policy']),
    'SessionList': obj({'items':{'type':'array','items':{'type':'object',
                        'required':['id','subject','role','created_at','last_seen','expires'],
                        'properties':{'id':S,'subject':S,'role':S,'created_at':{'type':'number'},
                                      'last_seen':{'type':'number'},'expires':{'type':'number'}}}}}, ['items']),
    'IdentityList': obj({'items':{'type':'array','items':ref('Identity')}}, ['items']),
    'RevokedSession': obj({'revoked':{'const':True}}, ['revoked']),
})
schemas.update({
    'SourceInput': obj({'name':S,'source_id':S,'collector_id':S,
                        'asset_ids':{'type':'array','minItems':1,'maxItems':100,'uniqueItems':True,'items':S}},
                       ['name','source_id','collector_id','asset_ids']),
    'Source': {'type':'object','required':['id','name','source_id','collector_id','asset_ids','enabled','version',
                                         'created_at','last_seen','accepted_count','duplicate_count'],
               'properties':{'id':S,'name':S,'source_id':S,'collector_id':S,'asset_ids':{'type':'array','items':S},
                             'enabled':{'type':'integer','enum':[0,1]},'version':I,'created_at':S,
                             'last_seen':{'type':['string','null']},'accepted_count':I,'duplicate_count':I}},
    'SourceList':obj({'items':{'type':'array','items':ref('Source')}},['items']),
    'SourceState':obj({'enabled':{'type':'boolean'},'reason':{'type':'string','minLength':1,'maxLength':1000}},
                      ['enabled','reason']),
    'QuotaInput':obj({'max_events_per_minute':{'type':'integer','minimum':1,'maximum':1000000},
                     'max_bytes_per_day':{'type':'integer','minimum':1024,'maximum':107374182400},
                     'max_pending':{'type':'integer','minimum':1,'maximum':1000000}},
                    ['max_events_per_minute','max_bytes_per_day','max_pending']),
    'Health':{'type':'object','required':['counts','stored_events','oldest_pending_seconds','worker','quotas',
                                       'profile','automatic_attempts','status'],
              'properties':{'counts':obj({k:I for k in ['pending','retry','dead','done']}, ['pending','retry','dead','done']),
                            'stored_events':I,'oldest_pending_seconds':{'type':['number','null']},
                            'worker':{'type':['object','null'],'properties':{'last_attempt':{'type':'number'},
                                  'last_success':{'type':['number','null']},'last_error_code':{'type':['string','null']}}},
                            'quotas':ref('Quotas'),'profile':{'const':'local-sqlite'},'automatic_attempts':{'const':3},
                            'status':enum('ok','backlog','degraded')}},
    'DeadLetters':obj({'items':{'type':'array','items':obj({'seq':I,'source_id':S,'event_id':S,'attempts':I,
                        'error_code':S,'work_revision':I,'accepted_at':{'type':'number'}},
                       ['seq','source_id','event_id','attempts','error_code','work_revision','accepted_at'])},
                       'next_cursor':{'type':['integer','null']}}, ['items','next_cursor']),
    'RetryDead':obj({'reason':{'type':'string','minLength':1,'maxLength':1000}},['reason']),
    'Requeued':obj({'sequence':I,'state':{'const':'pending'},'version':I},['sequence','state','version']),
})
schemas['Quotas']=obj(schemas['QuotaInput']['properties'] | {'version':I},
                     ['max_events_per_minute','max_bytes_per_day','max_pending','version'])
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
endpoint('identities','get','Учётные записи текущего тенанта без ключей',response='IdentityList')
endpoint('identities','post','Выдать лабораторный ключ один раз','IdentityInput','Identity')
endpoint('identities/{id}/rotate','post','Отозвать старый ключ и сеансы, выдать новый','RotateIdentity','Identity',version=True)
endpoint('identities/{id}/revoke','post','Отозвать доступ и закрыть сеансы','RevokeIdentity','Identity',version=True)
endpoint('identities/{id}/policy','post','Изменить атрибуты доступа и закрыть сеансы','ChangePolicy','Identity',version=True)
endpoint('sessions','get','Собственные сеансы или все сеансы для полного admin',response='SessionList')
endpoint('sessions/{id}/revoke','post','Завершить один разрешённый сеанс','Empty','RevokedSession')
endpoint('telemetry/sources','get','Зарегистрированные источники тенанта',response='SourceList')
endpoint('telemetry/sources','post','Привязать источник к collector и активам','SourceInput','Source')
endpoint('telemetry/sources/{id}/state','post','Приостановить или возобновить источник','SourceState','Source',version=True)
endpoint('telemetry/health','get','Состояние локального конвейера',response='Health')
endpoint('telemetry/quotas','get','Действующие квоты тенанта',response='Quotas')
endpoint('telemetry/quotas','post','Транзакционно изменить квоты','QuotaInput','Quotas',version=True)
endpoint('telemetry/dead-letters','get','Метаданные ошибок без raw payload',response='DeadLetters')
paths['/api/v1/telemetry/dead-letters']['get']['parameters']=[
    {'name':'after','in':'query','schema':{'type':'integer','minimum':0,'default':0}},
    {'name':'limit','in':'query','schema':{'type':'integer','minimum':1,'maximum':100,'default':50}},
]
endpoint('telemetry/dead-letters/{id}/retry','post','Повторить обработку без изменения исходного события',
         'RetryDead','Requeued',version=True)
for item in paths.values():
    for operation in item.values():
        operation['responses']['429']['headers']={'Retry-After':{'schema':{'type':'integer'},
            'description':'Рекомендуемый интервал повторного запроса в секундах; это не обещание освобождения квоты.'}}
contract={'openapi':'3.1.0','info':{'title':'BASTION GRID local lab API','version':'0.4.0',
 'description':'Контракт реализованного лабораторного подмножества. Отличия маршрутов от целевого RFP — ADR-004. Не production API.'},
 'servers':[{'url':'http://127.0.0.1:8080'}], 'paths':paths,
 'components':{'schemas':schemas,'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer'},
              'sessionCookie':{'type':'apiKey','in':'cookie','name':'bg_session'}}}}
if __name__=='__main__':
    Path('spec/openapi.json').write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n', encoding='utf-8', newline='\n')
