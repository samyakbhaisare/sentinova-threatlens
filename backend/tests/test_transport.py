import json
from types import SimpleNamespace

import httpx
import pytest

from app import feeds


def test_taxii_pagination_and_headers(monkeypatch):
    calls=[]
    responses=[{'objects':[{'type':'indicator','id':'indicator--one','pattern':"[domain-name:value = 'example.org']"}],'more':True,'next':'page two'}, {'objects':[],'more':False}]
    def fetch(url,**kwargs):
        calls.append((url,kwargs))
        return json.dumps(responses.pop(0))
    monkeypatch.setattr(feeds,'fetch',fetch)
    feed=SimpleNamespace(adapter='taxii',secret_ref='',url='https://taxii.example.org/collections/1/objects/')
    result=list(feeds.poll(feed))
    assert result[0]['value']=='example.org'
    assert calls[0][1]['headers']['Accept']=='application/taxii+json;version=2.1'
    assert 'next=page+two' in calls[1][0]


def test_credential_block_and_otx_pagination_loop(monkeypatch):
    monkeypatch.setattr(type(feeds.settings()),'secret',lambda self, name: '')
    with pytest.raises(ValueError,match='Missing credential'):
        list(feeds.poll(SimpleNamespace(adapter='otx',url='https://example.org',secret_ref='missing')))
    monkeypatch.setattr(feeds,'fetch',lambda *a,**k:'{"results":[],"next":"https://example.org"}')
    with pytest.raises(ValueError,match='pagination loop'):
        list(feeds.poll(SimpleNamespace(adapter='otx',url='https://example.org',secret_ref='')))


def test_dns_private_and_http_failure(monkeypatch):
    monkeypatch.setattr(feeds.socket,'getaddrinfo',lambda *a,**k:[(None,None,None,None,('127.0.0.1',443))])
    with pytest.raises(ValueError,match='Non-public'):
        feeds.validate_url('https://www.cisa.gov/feed')
    monkeypatch.setattr(feeds.socket,'getaddrinfo',lambda *a,**k:[(None,None,None,None,('1.1.1.1',443))])
    feeds.validate_url('https://www.cisa.gov/feed')
    real_client=httpx.Client
    monkeypatch.setattr(feeds.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(lambda request:httpx.Response(429,request=request)),**kwargs))
    from app.retry import DeferredRequest
    with pytest.raises(DeferredRequest):
        feeds.fetch('https://www.cisa.gov/feed')


def test_fetch_and_single_page(monkeypatch):
    monkeypatch.setattr(feeds,'validate_url',lambda _:None)
    real_client=httpx.Client
    monkeypatch.setattr(feeds.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(lambda request:httpx.Response(200,text='192.0.2.1\n',request=request)),**kwargs))
    assert list(feeds.poll(SimpleNamespace(adapter='ip_lines',secret_ref='',url='https://example.org')))[0]['value']=='192.0.2.1'


def test_slow_feed_has_an_overall_transfer_deadline(monkeypatch):
    monkeypatch.setattr(feeds,'validate_url',lambda _:None)
    moments=iter([0,100])
    monkeypatch.setattr(feeds,'monotonic',lambda:next(moments,100))
    original=httpx.Client
    monkeypatch.setattr(feeds.httpx,'Client',lambda **kwargs:original(transport=httpx.MockTransport(lambda request:httpx.Response(200,text='controlled',request=request)),**kwargs))
    with pytest.raises(ValueError,match='deadline'):
        feeds.fetch('https://example.org',max_seconds=90)
