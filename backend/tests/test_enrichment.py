"""Controlled provider fixtures only; no live enrichment or credentials are asserted."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from app import enrichment, feeds
from app.provider_results import normalize_result
from app.retry import DeferredRequest, retry_after

AT = datetime(2026, 7, 1, tzinfo=timezone.utc)


class MemoryCache:
    def __init__(self):
        self.values = {}
        self.expiry = {}
        self.clock = 0

    def get(self, key):
        return self.values.get(key) if self.expiry.get(key, 0) > self.clock else None

    def set(self, key, value, nx=False, ex=3600):
        if nx and self.get(key) is not None:
            return False
        self.values[key], self.expiry[key] = value, self.clock + ex
        return True

    def setex(self, key, delay, value):
        self.set(key, value, ex=delay)

    def ttl(self, key):
        return self.expiry.get(key, self.clock) - self.clock


def test_abuse_cache_isolates_ip_parameters_and_retains_observation_time(monkeypatch):
    cache, requests = MemoryCache(), []
    monkeypatch.setattr(enrichment.redis.Redis, 'from_url', lambda *a, **k: cache)
    monkeypatch.setattr(enrichment, 'now', lambda: AT)
    def request(url, **kwargs):
        address = kwargs['params']['ipAddress']
        requests.append(address)
        return httpx.Response(200, request=httpx.Request('GET', url), json={'data': {
            'abuseConfidenceScore': 90 if address == '192.0.2.1' else 10, 'totalReports': 5}})
    monkeypatch.setattr(enrichment.httpx, 'get', request)
    first, cached = enrichment.provider_request('abuseipdb', 'check', 'controlled-key', {'ipAddress': '192.0.2.1'})
    assert not cached and first['abuse_confidence'] == 90
    cache.clock += 3
    second, cached = enrichment.provider_request('abuseipdb', 'check', 'controlled-key', {'ipAddress': '192.0.2.2'})
    assert not cached and second['abuse_confidence'] == 10
    monkeypatch.setattr(enrichment, 'now', lambda: AT + timedelta(minutes=10))
    replay, cached = enrichment.provider_request('abuseipdb', 'check', 'controlled-key', {'ipAddress': '192.0.2.1'})
    assert cached and replay['abuse_confidence'] == 90 and replay['observed_at'] == AT.isoformat()
    assert requests == ['192.0.2.1', '192.0.2.2']


def test_provider_retry_after_is_shared_and_blocks_additional_calls(monkeypatch):
    cache, calls = MemoryCache(), []
    monkeypatch.setattr(enrichment.redis.Redis, 'from_url', lambda *a, **k: cache)
    def request(url, **kwargs):
        calls.append(url)
        return httpx.Response(429, headers={'Retry-After': '120'}, request=httpx.Request('GET', url))
    monkeypatch.setattr(enrichment.httpx, 'get', request)
    for address in ('192.0.2.1', '192.0.2.2'):
        with pytest.raises(DeferredRequest) as exc:
            enrichment.provider_request('abuseipdb', 'check', 'controlled-key', {'ipAddress': address})
        assert exc.value.seconds == 120
    assert len(calls) == 1


@pytest.mark.parametrize('value,expected', [('90', 90), ('NaN', 60), ('invalid', 60), ('-1', 1),
    ('Wed, 01 Jul 2026 00:02:00 GMT', 120)])
def test_retry_after_formats(value, expected):
    assert retry_after(value, at=AT) == expected


def test_domain_and_hash_verdicts_are_explainable_and_missing_data_unknown():
    data = normalize_result('virustotal', {'data': {'attributes': {'last_analysis_stats': {'malicious': 3, 'harmless': 7},
        'creation_date': (AT - timedelta(days=2)).timestamp(), 'categories': {'engine': 'phishing'}}}}, AT)
    assert data['verdict_ratio'] == .3 and data['normalized_reputation'] == 30
    assert data['newly_registered'] is True and data['known_phishing'] is True
    empty = normalize_result('virustotal', {'data': {'attributes': {}}}, AT)
    assert empty['newly_registered'] is None and empty['known_phishing'] is None
    assert empty['verdict_ratio'] is None and empty['normalized_reputation'] is None


@pytest.mark.parametrize('attrs', [
    {'last_analysis_stats': {'malicious': -1}}, {'last_analysis_stats': {'malicious': True}},
    {'last_analysis_stats': {'malicious': 1.5}}, {'creation_date': AT.timestamp() + 1},
    {'categories': ['phishing']},
])
def test_malformed_verdicts_never_enter_scoring(attrs):
    with pytest.raises(ValueError):
        normalize_result('virustotal', {'data': {'attributes': attrs}}, AT)


def test_geo_and_abuse_bounds():
    with pytest.raises(ValueError):
        normalize_result('ipwhois', {'success': True, 'latitude': 91, 'longitude': 0}, AT)
    with pytest.raises(ValueError):
        normalize_result('abuseipdb', {'data': {'abuseConfidenceScore': 101, 'totalReports': 1}}, AT)
    assert normalize_result('ipwhois', {'success': True, 'latitude': 0, 'longitude': 0, 'country_code': 'ZZ', 'connection': {'asn': 123}}, AT)['latitude'] == 0


def test_credentialed_pagination_cannot_change_origin(monkeypatch):
    calls = []
    monkeypatch.setattr(type(feeds.settings()), 'secret', lambda self, ref: 'controlled-key')
    def fetch(url, **kwargs):
        calls.append(url)
        return '{"results": [], "next": "https://www.cisa.gov/credential-collector"}'
    monkeypatch.setattr(feeds, 'fetch', fetch)
    with pytest.raises(ValueError, match='Cross-origin'):
        list(feeds.poll(SimpleNamespace(adapter='otx', secret_ref='test', url='https://otx.alienvault.com/api/v1/pulses/subscribed')))
    assert len(calls) == 1


def test_malwarebazaar_uses_documented_form_contract(monkeypatch):
    calls = []
    monkeypatch.setattr(type(feeds.settings()), 'secret', lambda self, ref: 'controlled-key')
    def fetch(url, **kwargs):
        calls.append(kwargs)
        return '{"query_status":"ok","data":[]}'
    monkeypatch.setattr(feeds, 'fetch', fetch)
    assert list(feeds.poll(SimpleNamespace(adapter='malwarebazaar', secret_ref='test', url='https://mb-api.abuse.ch/api/v1/'))) == []
    assert calls[0]['method'] == 'POST' and calls[0]['form'] == {'query': 'get_recent', 'selector': 'time'}


def test_private_ip_and_absent_keys_are_persisted_as_blocked(monkeypatch):
    rows = []
    db = SimpleNamespace(add=rows.append)
    ioc = SimpleNamespace(id='controlled', type='ip', value='192.0.2.1', reputation=0)
    assert enrichment.enrich(db, ioc)[0]['status'] == 'blocked'
    monkeypatch.setattr(type(enrichment.settings()), 'secret', lambda self, ref: '')
    monkeypatch.setattr(enrichment, 'rescore', lambda *a: None)
    ioc.type, ioc.value = 'hash_sha256', 'a' * 64
    assert enrichment.enrich(db, ioc)[0]['status'] == 'blocked'
    assert len(rows) == 2
