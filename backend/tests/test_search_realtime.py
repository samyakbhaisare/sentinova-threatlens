"""Protocol/dispatch contracts with explicit transport doubles; no live service claim."""
import json
from contextlib import nullcontext
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import main, search, tasks
from app.models import Outbox, SecurityEvent, now
from app.realtime import Hello, authorize_channels


def test_source_facets_match_feed_or_event_source_and_mapping_bounds():
    query=search.build_query('controlled',source='siem:controlled',type='ip',min_score=50)
    source_filter=query['bool']['filter'][-1]['bool']
    assert source_filter['minimum_should_match']==1
    assert source_filter['should']==[{'term':{'sources.keyword':'siem:controlled'}},{'term':{'source.keyword':'siem:controlled'}}]
    mapping=search.index_mapping()['mappings']
    assert mapping['dynamic'] is False and mapping['properties']['details']['enabled'] is False
    assert 'details_text' in query['bool']['must'][0]['simple_query_string']['fields']


def test_search_initialization_and_bulk_failure_are_not_silently_accepted(monkeypatch):
    requests=[]
    monkeypatch.setattr(search.settings(),'search_index','threatlens_test')
    original=httpx.Client
    def transport(request):
        requests.append(request)
        if request.method=='HEAD':return httpx.Response(404)
        if request.method=='PUT':return httpx.Response(200,json={'acknowledged':True})
        return httpx.Response(200,json={'errors':True,'items':[]})
    monkeypatch.setattr(search.httpx,'Client',lambda **kwargs:original(transport=httpx.MockTransport(transport),**kwargs))
    with pytest.raises(RuntimeError,match='outbox retained'):
        search.write_documents({'events-1':{'kind':'event','value':'controlled'}})
    assert requests[1].url.path=='/threatlens_test'
    metadata=json.loads(requests[2].content.decode().splitlines()[0])
    assert metadata['index']['_index']=='threatlens_test'
    assert search.event_channel()=='threatlens_test:events'


@pytest.mark.parametrize('fail_index',[True,False])
def test_outbox_indexes_before_publication_and_only_then_marks_delivered(monkeypatch,fail_index):
    rows=[Outbox(id='out-1',topic='events',object_id='event-1',delivered=False),Outbox(id='out-2',topic='alerts.stream',object_id='alert-1',delivered=False)]
    event=SecurityEvent(id='event-1',source='controlled',external_id='one',occurred_at=now(),created_at=now(),asset='controlled',observables=[],details={'test':True},controlled_test=True,digest='controlled')
    db=SimpleNamespace(scalars=lambda query:SimpleNamespace(all=lambda:rows),get=lambda model,key:event if key=='event-1' else SimpleNamespace(recipient_id='user-1'))
    monkeypatch.setattr(tasks,'Session',SimpleNamespace(begin=lambda:nullcontext(db)))
    calls=[]
    cache=SimpleNamespace(publish=lambda *args:calls.append('publish'),setex=lambda *args:None)
    monkeypatch.setattr(tasks.redis.Redis,'from_url',lambda *args,**kwargs:cache)
    def write(documents):
        calls.append('index')
        assert 'details_text' in documents['events-event-1']
        if fail_index:raise RuntimeError('controlled index outage')
    monkeypatch.setattr(tasks,'write_documents',write)
    if fail_index:
        with pytest.raises(RuntimeError):tasks.dispatch.run()
        assert calls==['index'] and not any(row.delivered for row in rows)
    else:
        tasks.dispatch.run()
        assert calls==['index','publish'] and all(row.delivered for row in rows)


@pytest.mark.parametrize('role,channel,allowed',[
    ('executive','alerts.stream',False),('soc_analyst','system.health',False),
    ('security_engineer','system.health',True),('soc_analyst','incidents.known',True),
    ('security_engineer','incidents.known',False),('administrator','incidents.missing',False),
])
def test_channel_permissions(role,channel,allowed):
    db=SimpleNamespace(get=lambda model,key:object() if key=='known' else None)
    user=SimpleNamespace(role=role)
    if allowed:authorize_channels(db,user,[channel])
    else:
        with pytest.raises(HTTPException):authorize_channels(db,user,[channel])


def test_websocket_hello_rejects_unbounded_or_malformed_subscriptions():
    from pydantic import ValidationError
    for payload in ({'access_token':'x','channels':[]},{'access_token':'x','channels':['a']*21},{'access_token':'x','channels':[42]},{'access_token':'x'*5000,'channels':['alerts.stream']}):
        with pytest.raises(ValidationError):Hello.model_validate(payload)


class Bus:
    def __init__(self,messages):self.messages=messages;self.subscribed=None
    def pubsub(self):return self
    async def subscribe(self,channel):self.subscribed=channel
    async def get_message(self,**kwargs):
        return {'data':json.dumps(self.messages.pop(0))} if self.messages else None
    async def aclose(self):return None


def test_websocket_delivery_honors_recipient_and_records_disconnect(monkeypatch):
    bus=Bus([{'channel':'alerts.stream','id':'other','recipient_id':'user-2'},
             {'channel':'alerts.stream','id':'mine','recipient_id':'user-1'}])
    monkeypatch.setattr(main.aioredis,'from_url',lambda *a,**k:bus)
    authenticated=[];audits=[]
    def authenticate(token,channels=None):
        authenticated.append((token,channels));return 'user-1','soc_analyst'
    monkeypatch.setattr(main,'authenticate_ws',authenticate)
    monkeypatch.setattr(main,'record_disconnect',lambda identity,accepted:audits.append((identity,accepted)))
    with TestClient(main.app) as client:
        with client.websocket_connect('/api/v1/ws') as ws:
            ws.send_json({'access_token':'controlled-token','channels':['alerts.stream']})
            assert ws.receive_json()['status']=='subscribed'
            assert ws.receive_json()['id']=='mine'
    assert authenticated[0][1]==['alerts.stream']
    assert audits==[('user-1',True)]
    assert bus.subscribed==search.event_channel()


def test_websocket_bad_credentials_close_and_are_audited(monkeypatch):
    bus=Bus([]);audits=[]
    monkeypatch.setattr(main.aioredis,'from_url',lambda *a,**k:bus)
    def reject(*args):raise HTTPException(401,'controlled authentication rejection')
    monkeypatch.setattr(main,'authenticate_ws',reject)
    monkeypatch.setattr(main,'record_disconnect',lambda identity,accepted:audits.append((identity,accepted)))
    with TestClient(main.app) as client:
        with client.websocket_connect('/api/v1/ws') as ws:
            ws.send_json({'access_token':'bad','channels':['alerts.stream']})
            with pytest.raises(WebSocketDisconnect):ws.receive_json()
    assert audits==[(None,False)] and bus.subscribed is None
