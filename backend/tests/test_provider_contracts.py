"""Provider and transport contract tests against documented response shapes.

No live provider credentials or endpoints are used.  Responses are synthetic
fixtures that mirror the official API documents; live entitlement remains a
separate, explicitly blocked verification.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from app import enrichment, feeds
from app.intelligence import ingest
from app.models import Feed, Indicator, Provenance
from sqlalchemy import func, select

AT = datetime(2026, 7, 1, tzinfo=timezone.utc)


class MemoryCache:
    def __init__(self):
        self.values, self.expiry, self.clock = {}, {}, 0

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


def wired(monkeypatch, handler):
    cache = MemoryCache()
    monkeypatch.setattr(enrichment.redis.Redis, 'from_url', lambda *a, **k: cache)
    monkeypatch.setattr(enrichment, 'now', lambda: AT)
    monkeypatch.setattr(enrichment.httpx, 'get', handler)
    return cache


def test_virustotal_contract_uses_header_auth_and_normalizes_file_verdicts(monkeypatch):
    calls = []

    def handler(url, headers, params, timeout, follow_redirects):
        calls.append({'url': url, 'headers': headers, 'params': params, 'timeout': timeout,
                      'follow_redirects': follow_redirects})
        return httpx.Response(200, request=httpx.Request('GET', url), json={
            'data': {'attributes': {'last_analysis_stats': {'malicious': 5, 'harmless': 5, 'suspicious': 0},
                                     'reputation': -20, 'categories': {'engine': 'malware'}}},
        })

    wired(monkeypatch, handler)
    digest = 'a' * 64
    data, cached = enrichment.provider_request('virustotal', 'files/' + digest, 'controlled-vt-key')
    assert cached is False
    assert calls[0]['url'] == 'https://www.virustotal.com/api/v3/files/' + digest
    assert calls[0]['headers'] == {'x-apikey': 'controlled-vt-key'}
    assert 'controlled-vt-key' not in calls[0]['url']
    assert calls[0]['timeout'] == 8 and calls[0]['follow_redirects'] is False
    assert data['engine_malicious'] == 5 and data['engine_total'] == 10
    assert data['verdict_ratio'] == 0.5 and data['normalized_reputation'] == 50
    assert data['status'] == 'ok' and data['observed_at'] == AT.isoformat()


def test_abuseipdb_contract_uses_key_header_and_maps_confidence(monkeypatch):
    calls = []

    def handler(url, headers, params, timeout, follow_redirects):
        calls.append({'url': url, 'headers': headers, 'params': params})
        return httpx.Response(200, request=httpx.Request('GET', url), json={'data': {
            'ipAddress': '198.51.100.7', 'isPublic': True, 'abuseConfidenceScore': 88,
            'totalReports': 42, 'numDistinctUsers': 9, 'isp': 'Controlled Transit',
        }})

    wired(monkeypatch, handler)
    data, _ = enrichment.provider_request('abuseipdb', 'check', 'controlled-abuse-key',
                                          {'ipAddress': '198.51.100.7', 'maxAgeInDays': 90})
    assert calls[0]['url'] == 'https://api.abuseipdb.com/api/v2/check'
    assert calls[0]['headers'] == {'Key': 'controlled-abuse-key', 'Accept': 'application/json'}
    assert calls[0]['params'] == {'ipAddress': '198.51.100.7', 'maxAgeInDays': 90}
    assert data['abuse_confidence'] == 88 and data['total_reports'] == 42
    assert data['owner'] == 'Controlled Transit' and data['normalized_reputation'] == 88


def test_ipwhois_contract_maps_geo_asn_and_owner(monkeypatch):
    calls = []

    def handler(url, headers, params, timeout, follow_redirects):
        calls.append({'url': url, 'headers': headers, 'params': params})
        return httpx.Response(200, request=httpx.Request('GET', url), json={
            'success': True, 'country_code': 'US', 'latitude': 37.7749, 'longitude': -122.4194,
            'connection': {'asn': 15169, 'org': 'Controlled Cloud'},
        })

    wired(monkeypatch, handler)
    data, _ = enrichment.provider_request('ipwhois', '198.51.100.7', '')
    assert calls[0]['url'] == 'https://ipwho.is/198.51.100.7' and calls[0]['headers'] == {}
    assert data['latitude'] == 37.7749 and data['longitude'] == -122.4194
    assert data['country'] == 'US' and data['asn'] == 15169 and data['owner'] == 'Controlled Cloud'


def test_provider_failure_and_cross_origin_guard(monkeypatch):
    def failing(url, **kwargs):
        return httpx.Response(500, request=httpx.Request('GET', url))

    wired(monkeypatch, failing)
    with pytest.raises(httpx.HTTPStatusError):
        enrichment.provider_request('virustotal', 'ip_addresses/198.51.100.7', 'controlled-vt-key')

    monkeypatch.setattr(type(feeds.settings()), 'secret', lambda self, ref: 'controlled-token')
    seen = []

    def fetch(url, **kwargs):
        seen.append(url)
        return '{"results": [], "next": "https://otx.alienvault.com.attacker.example/next"}'

    monkeypatch.setattr(feeds, 'fetch', fetch)
    with pytest.raises(ValueError, match='Cross-origin'):
        list(feeds.poll(SimpleNamespace(adapter='otx', secret_ref='test',
                                        url='https://otx.alienvault.com/api/v1/pulses/subscribed')))
    assert len(seen) == 1


TAXII_URL = 'https://taxii.controlled.example/collections/controlled/objects'
PAGE_TWO = {
    'more': False,
    'objects': [{
        'type': 'indicator', 'id': 'indicator--controlled-3',
        'pattern': "[file:hashes.'SHA-256' = '" + 'b' * 64 + "']", 'confidence': 90,
    }],
}
PAGE_ONE = {
    'more': True,
    'next': 'controlled-page-2',
    'objects': [
        {'type': 'marking-definition', 'id': 'marking-definition--amber', 'definition_type': 'tlp',
         'definition': {'tlp': 'amber'}},
        {'type': 'indicator', 'id': 'indicator--controlled-1',
         'pattern': "[domain-name:value = 'evil.controlled.example']", 'confidence': 80,
         'object_marking_refs': ['marking-definition--amber']},
        {'type': 'indicator', 'id': 'indicator--controlled-2',
         'pattern': "[ipv4-addr:value = '198.51.100.8']", 'confidence': 60},
    ],
}


def test_taxii_2_1_poll_contract_pagination_headers_and_normalization(monkeypatch):
    calls = []
    monkeypatch.setattr(type(feeds.settings()), 'secret', lambda self, ref: 'controlled-taxii-token')

    def fetch(url, **kwargs):
        calls.append({'url': url, **kwargs})
        import json
        return json.dumps(PAGE_ONE if len(calls) == 1 else PAGE_TWO)

    monkeypatch.setattr(feeds, 'fetch', fetch)
    records = list(feeds.poll(SimpleNamespace(adapter='taxii', secret_ref='taxii', url=TAXII_URL)))
    assert len(calls) == 2
    assert calls[0]['headers']['Accept'] == 'application/taxii+json;version=2.1'
    assert calls[0]['headers']['Authorization'] == 'Bearer controlled-taxii-token'
    assert 'Auth-Key' not in calls[0]['headers']
    assert calls[0]['method'] == 'GET'
    assert calls[1]['url'] == TAXII_URL + '?next=controlled-page-2'
    assert [(row['type'], row['value']) for row in records] == [
        ('domain', 'evil.controlled.example'), ('ip', '198.51.100.8'), ('hash_sha256', 'b' * 64),
    ]
    assert records[0]['reference'] == 'indicator--controlled-1' and records[0]['tlp'] == 'amber'
    assert records[1]['tlp'] == 'clear'


def test_taxii_ingestion_persists_canonical_indicators_and_provenance(db):
    feed = Feed(name='CONTROLLED TAXII COLLECTION', adapter='taxii', url=TAXII_URL, reliability=80, ttl_days=30)
    db.add(feed)
    db.flush()
    from app.feeds import stix_records
    records = list(stix_records(PAGE_ONE['objects'] + PAGE_TWO['objects']))
    first = [ingest(db, feed, row) for row in records]
    second = [ingest(db, feed, row) for row in records]
    assert [row.id for row in first] == [row.id for row in second]
    db.expire_all()
    controlled_values = {row['value'] for row in records}
    assert db.scalar(select(func.count()).select_from(Indicator).where(Indicator.value.in_(controlled_values))) == 3
    assert db.scalar(select(func.count()).select_from(Provenance).where(Provenance.feed_id == feed.id)) == 3
    amber = db.scalar(select(Indicator).where(Indicator.value == 'evil.controlled.example'))
    assert amber.tlp == 'amber' and amber.category == 'unknown'
    references = set(db.scalars(select(Provenance.reference).where(Provenance.feed_id == feed.id)).all())
    assert references == {'indicator--controlled-1', 'indicator--controlled-2', 'indicator--controlled-3'}
