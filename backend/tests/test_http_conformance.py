"""Real-HTTP provider/TAXII conformance servers (not live vendor credentials).

These tests bind loopback stub servers that implement the documented provider
and TAXII 2.1 response shapes.  The production transport code is exercised over
TCP, including headers, pagination, normalisation and PostgreSQL persistence.
Nothing here claims a live VirusTotal/AbuseIPDB/geo/TAXII subscription.
"""
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import func, select

from app import enrichment, feeds
from app.intelligence import ingest
from app.models import Enrichment, Feed, Indicator, Provenance

AT = datetime(2026, 11, 9, tzinfo=timezone.utc)
TOKEN = 'controlled-taxii-bearer-token'
PAGE = 'controlled-page-2'


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


class Recorder:
    def __init__(self):
        self.requests = []


@contextmanager
def http_server(responder):
    recorder = Recorder()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            recorder.requests.append({'path': self.path, 'headers': dict(self.headers)})
            status, headers, body = responder(self.path, dict(self.headers))
            encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def provider_responder(path, headers):
    if path.startswith('/api/v3/ip_addresses/'):
        return 200, {'Content-Type': 'application/json'}, {'data': {'attributes': {
            'last_analysis_stats': {'malicious': 4, 'harmless': 6}, 'reputation': -10, 'categories': {}}}}
    if path.startswith('/api/v3/domains/'):
        created = (AT - timedelta(days=2)).timestamp()
        return 200, {'Content-Type': 'application/json'}, {'data': {'attributes': {
            'last_analysis_stats': {'malicious': 8, 'harmless': 2}, 'creation_date': created,
            'categories': {'controlled-engine': 'phishing'}}}}
    if path.startswith('/api/v3/files/'):
        return 200, {'Content-Type': 'application/json'}, {'data': {'attributes': {
            'last_analysis_stats': {'malicious': 70, 'harmless': 5}, 'categories': {}}}}
    if path.startswith('/api/v2/check'):
        query = parse_qs(urlsplit(path).query)
        return 200, {'Content-Type': 'application/json'}, {'data': {
            'ipAddress': query['ipAddress'][0], 'abuseConfidenceScore': 87, 'totalReports': 12,
            'isp': 'Controlled Transit'}}
    if path == '/9.9.9.9':
        return 200, {'Content-Type': 'application/json'}, {
            'success': True, 'country_code': 'US', 'latitude': 37.7749, 'longitude': -122.4194,
            'connection': {'asn': 15169, 'org': 'Controlled Cloud'}}
    return 404, {'Content-Type': 'application/json'}, {'error': 'not found'}


TAXII_OBJECTS = [
    {'type': 'marking-definition', 'id': 'marking-definition--amber', 'definition_type': 'tlp',
     'definition': {'tlp': 'amber'}},
    {'type': 'indicator', 'id': 'indicator--http-1', 'confidence': 80,
     'pattern': "[domain-name:value = 'evil.http.example']",
     'object_marking_refs': ['marking-definition--amber']},
    {'type': 'indicator', 'id': 'indicator--http-2', 'confidence': 60,
     'pattern': "[ipv4-addr:value = '9.9.9.9']"},
]
TAXII_PAGE_TWO = [
    {'type': 'indicator', 'id': 'indicator--http-3', 'confidence': 90,
     'pattern': "[file:hashes.'SHA-256' = '" + 'c' * 64 + "']"},
]


def taxii_responder(path, headers):
    if headers.get('Authorization') != 'Bearer ' + TOKEN:
        return 401, {'Content-Type': 'application/json'}, {'title': 'unauthorized'}
    if headers.get('Accept') != 'application/taxii+json;version=2.1':
        return 406, {'Content-Type': 'application/json'}, {'title': 'not acceptable'}
    next_token = parse_qs(urlsplit(path).query).get('next', [None])[0]
    if next_token == PAGE:
        return 200, {'Content-Type': 'application/taxii+json;version=2.1'}, {'more': False, 'objects': TAXII_PAGE_TWO}
    return 200, {'Content-Type': 'application/taxii+json;version=2.1'}, {
        'more': True, 'next': PAGE, 'objects': TAXII_OBJECTS}


def test_real_http_enrichment_for_ip_domain_and_hash(db, monkeypatch):
    monkeypatch.setattr(enrichment.redis.Redis, 'from_url', lambda *a, **k: MemoryCache())
    monkeypatch.setattr(enrichment, 'now', lambda: AT)
    monkeypatch.setattr(type(enrichment.settings()), 'secret', lambda self, ref: 'controlled-' + ref)
    config = enrichment.settings()
    monkeypatch.setattr(config, 'geolocation_enabled', True)
    with http_server(provider_responder) as (base, recorder):
        monkeypatch.setattr(config, 'virustotal_base_url', base + '/api/v3/')
        monkeypatch.setattr(config, 'abuseipdb_base_url', base + '/api/v2/')
        monkeypatch.setattr(config, 'ipwhois_base_url', base + '/')
        ip = Indicator(type='ip', value='9.9.9.9', tlp='clear', reputation=0, confidence=50,
                       expires_at=AT + timedelta(days=30), first_seen=AT, last_seen=AT, category='suspicious')
        domain = Indicator(type='domain', value='evil.http.example', tlp='clear', reputation=0, confidence=50,
                           expires_at=AT + timedelta(days=30), first_seen=AT, last_seen=AT, category='phishing')
        digest = Indicator(type='hash_sha256', value='d' * 64, tlp='clear', reputation=0, confidence=50,
                           expires_at=AT + timedelta(days=30), first_seen=AT, last_seen=AT, category='malware')
        db.add_all([ip, domain, digest])
        db.flush()

        ip_results = {row['provider']: row for row in enrichment.enrich(db, ip)}
        domain_results = {row['provider']: row for row in enrichment.enrich(db, domain)}
        hash_results = {row['provider']: row for row in enrichment.enrich(db, digest)}
        db.flush()

        assert ip_results['abuseipdb']['abuse_confidence'] == 87
        assert ip_results['abuseipdb']['total_reports'] == 12
        assert ip_results['ipwhois']['latitude'] == 37.7749
        assert ip_results['ipwhois']['asn'] == 15169 and ip_results['ipwhois']['owner'] == 'Controlled Cloud'
        assert domain_results['virustotal']['newly_registered'] is True
        assert domain_results['virustotal']['known_phishing'] is True
        assert hash_results['virustotal']['engine_malicious'] == 70
        assert hash_results['virustotal']['engine_total'] == 75
        assert hash_results['virustotal']['verdict_ratio'] == pytest.approx(70 / 75)

        # Credentials travelled in headers only; never in URLs.
        assert all('controlled-virustotal_key' not in row['path'] for row in recorder.requests)
        vt = next(row for row in recorder.requests if '/api/v3/files/' in row['path'])
        abuse = next(row for row in recorder.requests if '/api/v2/check' in row['path'])
        assert vt['headers'].get('x-apikey') == 'controlled-virustotal_key'
        assert abuse['headers'].get('Key') == 'controlled-abuseipdb_key'
        assert abuse['headers'].get('Accept') == 'application/json'

        stored = db.scalars(select(Enrichment).where(Enrichment.indicator_id == ip.id)).all()
        assert {row.provider for row in stored} == {'abuseipdb', 'ipwhois', 'virustotal'}
        assert all(row.data['status'] == 'ok' for row in stored)
        assert ip.reputation == 87
        assert domain.reputation == 80
        assert digest.reputation == 93


def test_real_http_taxii_2_1_pagination_auth_and_ingestion(db, monkeypatch):
    with http_server(taxii_responder) as (base, recorder):
        taxii_url = base + '/collections/controlled/objects'
        # The production SSRF guard rejects loopback; this test explicitly bypasses
        # it to reach the conformance server.  The guard itself is covered separately.
        monkeypatch.setattr(feeds, 'validate_url', lambda _url: None)
        monkeypatch.setattr(type(feeds.settings()), 'secret', lambda self, ref: TOKEN)
        feed = SimpleNamespace(adapter='taxii', secret_ref='taxii', url=taxii_url)
        records = list(feeds.poll(feed))

        assert len(recorder.requests) == 2
        assert 'next=' + PAGE.replace('-', '-') in recorder.requests[1]['path']
        assert recorder.requests[0]['headers']['Accept'] == 'application/taxii+json;version=2.1'
        assert recorder.requests[0]['headers']['Authorization'] == 'Bearer ' + TOKEN
        assert [(row['type'], row['value']) for row in records] == [
            ('domain', 'evil.http.example'), ('ip', '9.9.9.9'), ('hash_sha256', 'c' * 64)]
        assert records[0]['tlp'] == 'amber' and records[0]['reference'] == 'indicator--http-1'

        row = Feed(name='CONTROLLED HTTP TAXII', adapter='taxii', url=taxii_url, reliability=80, ttl_days=30)
        db.add(row)
        db.flush()
        first = [ingest(db, row, record) for record in records]
        second = [ingest(db, row, record) for record in records]
        assert [item.id for item in first] == [item.id for item in second]
        db.expire_all()
        values = {record['value'] for record in records}
        assert db.scalar(select(func.count()).select_from(Indicator).where(Indicator.value.in_(values))) == 3
        assert db.scalar(select(func.count()).select_from(Provenance).where(Provenance.feed_id == row.id)) == 3
        amber = db.scalar(select(Indicator).where(Indicator.value == 'evil.http.example'))
        assert amber.tlp == 'amber'
        references = set(db.scalars(select(Provenance.reference).where(Provenance.feed_id == row.id)).all())
        assert references == {'indicator--http-1', 'indicator--http-2', 'indicator--http-3'}
