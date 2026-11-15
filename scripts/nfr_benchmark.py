"""Measured NFR benchmark against an isolated PostgreSQL database and search index.

This script never touches the production database or the production search index.
It seeds clearly prefixed synthetic rows into ``threatlens_test``, starts a local
API on port 8103, measures read/search latency, measures the ingestion pipeline,
then removes the rows it created.

Targets that cannot be proven in this environment (10M documents, 200 users,
monthly uptime, real TLS/cloud deployment) are reported as NOT MEASURED rather
than inferred from these results.
"""
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy import create_engine, delete, insert, select, update
from sqlalchemy.engine import make_url

from nfr_common import (ResourceMonitor, build_search_index, child_pids, ensure_port_free, hardware,
                        measure_reads, search_index_stats)

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr' + secrets.token_hex(4)
SEARCH_INDEX = os.environ.get('NFR_SEARCH_INDEX', 'threatlens_nfr_' + RUN)
BUILD_SEARCH = os.environ.get('NFR_BUILD_SEARCH', '1') != '0'
API_PORT = int(os.environ.get('NFR_API_PORT', '8103'))
API_URL = f'http://127.0.0.1:{API_PORT}'
INDICATORS = int(os.environ.get('NFR_INDICATORS', '12000'))
ALERTS = 1000
INCIDENTS = 500
SEARCH_DOCS = int(os.environ.get('NFR_SEARCH_DOCS', '100000'))
SEARCH_BATCH = int(os.environ.get('NFR_SEARCH_BATCH', '10000'))
SEARCH_REQUESTS = int(os.environ.get('NFR_SEARCH_REQUESTS', '400'))
SEARCH_CONCURRENCY = int(os.environ.get('NFR_SEARCH_CONCURRENCY', '20'))
SEARCH_QUERY = os.environ.get('NFR_SEARCH_QUERY', 'bench')
SEARCH_PATH = '/api/v1/search?q=' + SEARCH_QUERY + '&type=domain'
INGEST_RECORDS = int(os.environ.get('NFR_INGEST_RECORDS', '1000'))
CONCURRENCY = int(os.environ.get('NFR_CONCURRENCY', '20'))
REQUESTS_PER_ENDPOINT = int(os.environ.get('NFR_REQUESTS', '400'))
THINK_TIME = int(os.environ.get('NFR_THINK_TIME_MS', '0')) / 1000
RESOURCE_INTERVAL = int(os.environ.get('NFR_RESOURCE_INTERVAL', '10'))
DB_POOL_SIZE = int(os.environ.get('NFR_DB_POOL_SIZE', '25'))
DB_MAX_OVERFLOW = int(os.environ.get('NFR_DB_MAX_OVERFLOW', '40'))
CONTAINERS = os.environ.get('NFR_CONTAINERS', 'sentinova-nfr-es,sentinova-threatlens-postgres-1,sentinova-threatlens-redis-1').split(',')

# Point every app module at the isolated test database BEFORE importing them.
_test_url = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test')
os.environ['DATABASE_URL'] = _test_url.render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['SEARCH_INDEX'] = SEARCH_INDEX
os.environ['TEST_MODE'] = 'true'
os.environ['DB_POOL_SIZE'] = str(DB_POOL_SIZE)
os.environ['DB_MAX_OVERFLOW'] = str(DB_MAX_OVERFLOW)
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if _test_url.database != 'threatlens_test':
    raise SystemExit('Refusing to benchmark against a non-test database')

from app.db import Session  # noqa: E402
from app.intelligence import ingest  # noqa: E402
from app.models import (Alert, AlertRule, Enrichment, Feed, Incident, Indicator,  # noqa: E402
                        Notification, Outbox, Provenance, Refresh, User, now, uid)
from app.security import hasher  # noqa: E402


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[position], 2)


def database_url():
    url = make_url(os.environ['DATABASE_URL'])
    if url.database != 'threatlens_test':
        raise RuntimeError('Benchmark database must be threatlens_test')
    return url.render_as_string(hide_password=False)


def bulk(engine, table, rows, size=2000):
    with engine.begin() as db:
        for start in range(0, len(rows), size):
            db.execute(insert(table), rows[start:start + size])


def seed(engine, user_id):
    stamp = now()
    feeds = [dict(id=uid(), name=f'{RUN.upper()} SOURCE {i}', adapter='json', url='internal',
                  secret_ref='', interval_seconds=3600, ttl_days=30, enabled=False,
                  next_poll=stamp, ingested=0, rejected=0, reliability=50) for i in range(6)]
    bulk(engine, Feed.__table__, feeds)
    indicators, provenance = [], []
    for i in range(INDICATORS):
        identifier = uid()
        value = f'2001:db8:0:{RUN[3:7]}:{RUN[7:11]}::{i:x}'
        indicators.append(dict(id=identifier, type='ip', value=value, score=40 + i % 60, confidence=50,
                               reputation=50, breakdown={}, tlp='clear', notes_tlp='amber', version=1,
                               status='active', category=['malware', 'phishing', 'botnet'][i % 3], tags=[],
                               techniques=[], notes='', first_seen=stamp, last_seen=stamp,
                               expires_at=stamp + timedelta(days=30), updated_at=stamp))
        provenance.append(dict(id=uid(), indicator_id=identifier, feed_id=feeds[i % 6]['id'], confidence=50,
                               tlp='clear', reference=RUN, last_seen=stamp))
    bulk(engine, Indicator.__table__, indicators)
    bulk(engine, Provenance.__table__, provenance)
    rule = dict(id=uid(), name=f'{RUN.upper()} ALERT RULE', min_score=0, min_sightings=0,
                category=None, feed_id=None, recipient_id=user_id, enabled=True, version=1)
    bulk(engine, AlertRule.__table__, [rule])
    alerts = [dict(id=uid(), indicator_id=indicators[i]['id'], rule_id=rule['id'], score=indicators[i]['score'],
                   state=['new', 'acknowledged', 'in-progress', 'resolved', 'closed'][i % 5],
                   assignee_id=user_id, recipient_id=user_id, updated_at=stamp, version=1) for i in range(ALERTS)]
    bulk(engine, Alert.__table__, alerts)
    incidents = [dict(id=uid(), title=f'{RUN.upper()} INCIDENT {i}', state=['open', 'resolved', 'closed'][i % 3],
                      owner_id=user_id, creator_id=user_id, checklist={}, tlp='amber', version=1)
                 for i in range(INCIDENTS)]
    bulk(engine, Incident.__table__, incidents)
    bulk(engine, Notification.__table__, [dict(id=uid(), user_id=user_id, alert_id=alerts[i]['id'], read=False)
                                          for i in range(ALERTS)])
    return [row['id'] for row in indicators], [row['id'] for row in alerts], \
        [row['id'] for row in incidents], [row['id'] for row in feeds], rule['id']


def cleanup(engine, user_id, indicator_ids, alert_ids, incident_ids, feed_ids, rule_id):
    """Remove synthetic business rows.

    ``audit_log`` and ``incident_timeline`` are append-only by trigger and by
    grant (``deploy/grants.sql``), so audit evidence is intentionally retained in
    the isolated test database.  That also means the synthetic benchmark account
    cannot be deleted: ``audit_log.actor_id`` references it.  The account is
    therefore deterministic and reused by later runs.
    """
    with engine.begin() as db:
        if incident_ids:
            db.execute(delete(Incident).where(Incident.id.in_(incident_ids)))
        if alert_ids:
            db.execute(delete(Notification).where(Notification.alert_id.in_(alert_ids)))
            db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
        if rule_id:
            db.execute(delete(AlertRule).where(AlertRule.id == rule_id))
        if indicator_ids:
            db.execute(delete(Enrichment).where(Enrichment.indicator_id.in_(indicator_ids)))
            db.execute(delete(Provenance).where(Provenance.indicator_id.in_(indicator_ids)))
            db.execute(delete(Outbox).where(Outbox.object_id.in_(indicator_ids)))
            db.execute(delete(Indicator).where(Indicator.id.in_(indicator_ids)))
        if feed_ids:
            db.execute(delete(Feed).where(Feed.id.in_(feed_ids)))
        db.execute(delete(Refresh).where(Refresh.user_id == user_id))


def create_user(engine, password):
    """Create or reuse the deterministic synthetic benchmark administrator."""
    email = 'nfr-benchmark@example.org'
    with engine.begin() as db:
        user_id = db.scalar(select(User.id).where(User.email == email))
        values = dict(name='CONTROLLED NFR BENCHMARK', role='administrator',
                      password_hash=hasher.hash(password), enabled=True, token_version=1, layout=[])
        if user_id:
            db.execute(update(User).where(User.id == user_id).values(**values))
        else:
            user_id = uid()
            db.execute(insert(User), [dict(id=user_id, email=email, **values)])
    return user_id


def start_api(env):
    ensure_port_free(API_PORT)
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-api.log').open('ab')
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
                                '--port', str(API_PORT), '--log-level', 'warning'],
                               cwd=ROOT / 'backend', stdout=log, stderr=log, env=env)
    for _ in range(80):
        try:
            if httpx.get(API_URL + '/health/live', timeout=1).status_code == 200:
                return process
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    process.terminate()
    raise RuntimeError('Benchmark API did not become ready')


def measure(client, headers, path, requests_total, concurrency):
    """Kept for the historical call signature; delegates to the shared harness."""
    return measure_reads(headers, API_URL, path, requests_total, concurrency, think_time=THINK_TIME)


def ingest_measure(engine):
    feed_id = uid()
    stamp = now()
    with engine.begin() as db:
        db.execute(insert(Feed), [dict(id=feed_id, name=f'{RUN.upper()} INGEST', adapter='json', url='internal',
                                       secret_ref='', interval_seconds=3600, ttl_days=30, enabled=False,
                                       next_poll=stamp, ingested=0, rejected=0, reliability=50)])
    records = [{'type': 'ip', 'value': f'2001:db8:1:{RUN[3:7]}:{RUN[7:11]}::{i:x}', 'confidence': 60,
                'category': 'benchmark'} for i in range(INGEST_RECORDS)]
    started = time.perf_counter()
    identifiers = []
    with Session.begin() as db:
        feed = db.get(Feed, feed_id)
        for record in records:
            identifiers.append(ingest(db, feed, record).id)
    elapsed = time.perf_counter() - started
    throughput = INGEST_RECORDS / elapsed
    replay_started = time.perf_counter()
    with Session.begin() as db:
        feed = db.get(Feed, feed_id)
        for record in records:
            ingest(db, feed, record)
    replay_elapsed = time.perf_counter() - replay_started
    with engine.begin() as db:
        db.execute(delete(Enrichment).where(Enrichment.indicator_id.in_(identifiers)))
        db.execute(delete(Provenance).where(Provenance.feed_id == feed_id))
        db.execute(delete(Outbox).where(Outbox.object_id.in_(identifiers)))
        db.execute(delete(Indicator).where(Indicator.id.in_(identifiers)))
        db.execute(delete(Feed).where(Feed.id == feed_id))
    return {'records': INGEST_RECORDS, 'unique_seconds': round(elapsed, 3),
            'unique_records_per_second': round(throughput, 1),
            'extrapolated_unique_per_hour': round(throughput * 3600),
            'replay_seconds': round(replay_elapsed, 3),
            'replay_records_per_second': round(INGEST_RECORDS / replay_elapsed, 1),
            'note': 'single process, real PostgreSQL, synthetic indicators, automatic enrichment queue enabled'}


def main():
    os.environ['DATABASE_URL'] = database_url()
    os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
    os.environ['SEARCH_INDEX'] = SEARCH_INDEX
    os.environ['TEST_MODE'] = 'true'
    os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
    from app.config import settings
    settings.cache_clear()
    engine = create_engine(os.environ['DATABASE_URL'])
    from app.db import Base
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    (ROOT / 'artifacts' / 'verification').mkdir(parents=True, exist_ok=True)
    result = {'run': RUN, 'hardware': hardware(),
              'dataset': {'indicators': INDICATORS, 'alerts': ALERTS, 'incidents': INCIDENTS,
                          'search_documents': SEARCH_DOCS},
              'concurrency': CONCURRENCY, 'requests_per_endpoint': REQUESTS_PER_ENDPOINT,
              'virtual_user_think_time_ms': round(THINK_TIME * 1000, 1),
              'database_pool': {'size': DB_POOL_SIZE, 'max_overflow': DB_MAX_OVERFLOW},
              'search_url': os.environ['SEARCH_URL'], 'search_index': SEARCH_INDEX,
              'isolated_database': 'threatlens_test', 'redis_database': 3}
    password = secrets.token_urlsafe(24)
    user_id = create_user(engine, password)
    indicator_ids, alert_ids, incident_ids, feed_ids, rule_id = seed(engine, user_id)
    api = None
    monitor = None
    try:
        api = start_api(os.environ.copy())
        monitor = ResourceMonitor(CONTAINERS, pids=child_pids(api.pid) + [api.pid], interval=RESOURCE_INTERVAL)
        monitor.start()
        with httpx.Client() as client:
            login = client.post(API_URL + '/api/v1/auth/login', json={'email': 'nfr-benchmark@example.org', 'password': password}, timeout=15)
            login.raise_for_status()
            headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
            result['read_latency'] = {}
            for path in ['/api/v1/dashboard', '/api/v1/indicators?limit=50', '/api/v1/alerts',
                         '/api/v1/incidents', '/api/v1/assignees', '/api/v1/notifications']:
                result['read_latency'][path] = measure(client, headers, path, REQUESTS_PER_ENDPOINT, CONCURRENCY)
            try:
                if BUILD_SEARCH:
                    indexed = build_search_index(os.environ['SEARCH_URL'], SEARCH_INDEX, SEARCH_DOCS, SEARCH_BATCH)
                else:
                    indexed = search_index_stats(os.environ['SEARCH_URL'], SEARCH_INDEX)
                    if indexed['count'] < SEARCH_DOCS:
                        raise RuntimeError(f"reused index has {indexed['count']} < {SEARCH_DOCS} documents")
                result['search'] = {**indexed, 'reused_index': not BUILD_SEARCH,
                                    'note': 'isolated synthetic index; production PRD target is 10M+',
                                    'query': SEARCH_PATH,
                                    **measure(client, headers, SEARCH_PATH,
                                              SEARCH_REQUESTS, SEARCH_CONCURRENCY)}
            except Exception as exc:  # noqa: BLE001
                result['search'] = {'error': type(exc).__name__ + ': ' + str(exc)[:300]}
            started = time.perf_counter()
            exported = client.get(API_URL + '/api/v1/export/csv', headers=headers, timeout=60)
            export_seconds = time.perf_counter() - started
            result['export'] = {'status': exported.status_code, 'seconds': round(export_seconds, 3),
                                'rows': max(0, len(exported.text.splitlines()) - 1),
                                'bytes': len(exported.content), 'api_row_cap': 1000}
    finally:
        if monitor:
            monitor.stop()
            result['resources'] = monitor.summarize()
        if api:
            api.terminate()
            api.wait(timeout=15)
        try:
            if BUILD_SEARCH:
                import httpx as es_client
                es_client.delete(os.environ['SEARCH_URL'] + '/' + SEARCH_INDEX, timeout=120)
        except Exception:  # noqa: BLE001
            pass
        cleanup(engine, user_id, indicator_ids, alert_ids, incident_ids, feed_ids, rule_id)
        engine.dispose()
    result['cleanup'] = {'synthetic_business_rows_removed': True,
                         'append_only_evidence_retained': ['audit_log', 'incident_timeline'],
                         'benchmark_account_retained': 'nfr-benchmark@example.org (referenced by audit evidence)',
                         'isolated_search_index_removed': BUILD_SEARCH}
    result['ingestion'] = ingest_measure(create_engine(database_url()))
    result['not_measured'] = [
        'horizontal scaling across multiple API replicas (single local uvicorn process)',
        'monthly 99.5% availability (no sustained production monitoring window)',
        'real TLS 1.2+ termination in this JSON (separate TLS drill artifact)',
        'Kubernetes/cloud rollout (no cluster available; manifests rendered/dry-run only)',
    ]
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-nfr-benchmark.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
