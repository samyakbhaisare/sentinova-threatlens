"""Measured ingest -> outbox -> Redis -> authenticated WebSocket latency.

The API and the outbox dispatcher both run against ``threatlens_test`` and Redis
logical database 3.  Synthetic indicators, rules, events and alerts are removed
after the run; append-only audit evidence remains in the isolated test database.

This measures the server-side part of FR-15/NFR-02.  The browser DOM part is
measured separately by ``scripts/latency_ui.mjs`` against the same isolated API.
"""
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy import create_engine, delete, insert, select, update
from sqlalchemy.engine import make_url
from websockets.sync.client import connect

from nfr_common import ResourceMonitor, child_pids, ensure_port_free, hardware, percentile

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr-latency-' + secrets.token_hex(4)
SEARCH_INDEX = 'threatlens_nfr_' + RUN.replace('-', '_')
API_PORT = int(os.environ.get('NFR_LATENCY_PORT', '8105'))
API_URL = f'http://127.0.0.1:{API_PORT}'
ITERATIONS = int(os.environ.get('NFR_LATENCY_ITERATIONS', '20'))
RESOURCE_INTERVAL = int(os.environ.get('NFR_RESOURCE_INTERVAL', '5'))
ORIGIN = os.environ.get('ORIGIN', 'http://localhost:3000')
CONTAINERS = os.environ.get('NFR_CONTAINERS', 'sentinova-threatlens-postgres-1,sentinova-threatlens-redis-1').split(',')

_test_url = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test')
os.environ['DATABASE_URL'] = _test_url.render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['SEARCH_INDEX'] = SEARCH_INDEX
os.environ['TEST_MODE'] = 'true'
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if _test_url.database != 'threatlens_test':
    raise SystemExit('Refusing to benchmark against a non-test database')

from app.config import settings  # noqa: E402
from app.db import Session  # noqa: E402
from app.models import (Alert, AlertRule, Enrichment, EventObservable, Feed, Indicator, Notification, Outbox,  # noqa: E402
                        Provenance, Refresh, SecurityEvent, Sighting, User, now, uid)
from app.security import hasher, issue  # noqa: E402
from app.tasks import dispatch  # noqa: E402


def ensure_user(engine):
    email = 'nfr-latency@example.org'
    password = secrets.token_urlsafe(24)
    with engine.begin() as db:
        identifier = db.scalar(select(User.id).where(User.email == email))
        values = dict(name='CONTROLLED LATENCY BENCHMARK', role='administrator',
                      password_hash=hasher.hash(password), enabled=True, token_version=1, layout=[])
        if identifier:
            db.execute(update(User).where(User.id == identifier).values(**values))
        else:
            identifier = uid()
            db.execute(insert(User), [dict(id=identifier, email=email, **values)])
    return identifier, password


def seed_rule(engine, user_id):
    rule_id = uid()
    with engine.begin() as db:
        db.execute(insert(AlertRule), [dict(id=rule_id, name=f'{RUN.upper()} LATENCY RULE', min_score=50,
                                            min_sightings=0, category=None, feed_id=None, recipient_id=user_id,
                                            enabled=True, version=1)])
    return rule_id


def seed_case(engine, index):
    stamp = now()
    raw_value = f'2001:db8:4:{RUN[14:18]}:{RUN[18:22]}::{index:x}'
    from app.intelligence import canonical
    value = canonical('ip', raw_value)  # event observables are canonicalized on insert
    with engine.begin() as db:
        feed_id = uid()
        db.execute(insert(Feed), [dict(id=feed_id, name=f'{RUN.upper()} LATENCY {index}', adapter='json',
                                       url='internal', secret_ref='', interval_seconds=3600, ttl_days=30,
                                       enabled=False, next_poll=stamp, ingested=0, rejected=0, reliability=90)])
        indicator_id = uid()
        db.execute(insert(Indicator), [dict(id=indicator_id, type='ip', value=value, score=95, confidence=95,
                                           reputation=95, breakdown={}, tlp='clear', notes_tlp='clear', version=1,
                                           status='active', category='malware', tags=[], techniques=[], notes='',
                                           first_seen=stamp, last_seen=stamp, expires_at=stamp + timedelta(days=30),
                                           updated_at=stamp)])
        db.execute(insert(Provenance), [dict(id=uid(), indicator_id=indicator_id, feed_id=feed_id, confidence=95,
                                             tlp='clear', reference=RUN, last_seen=stamp)])
    return {'feed_id': feed_id, 'indicator_id': indicator_id, 'value': value,
            'raw_value': raw_value, 'external_id': f'{RUN}-event-{index}'}


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
    raise RuntimeError('Latency benchmark API did not become ready')


class Dispatcher(threading.Thread):
    """Run the real outbox dispatcher task in-process against isolated services."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop_event, self.errors = threading.Event(), []

    def run(self):
        while not self.stop_event.is_set():
            started = time.perf_counter()
            try:
                dispatch()
            except Exception as exc:  # noqa: BLE001 - recorded, never hidden
                self.errors.append({'error_type': type(exc).__name__, 'detail': str(exc)[:200]})
            elapsed = time.perf_counter() - started
            self.stop_event.wait(max(0.02, 0.1 - elapsed))

    def stop(self):
        self.stop_event.set()
        self.join(timeout=10)


def main():
    settings.cache_clear()
    engine = create_engine(os.environ['DATABASE_URL'])
    from app.db import Base
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    identifier = ensure_user(engine)[0]
    rule_id = seed_rule(engine, identifier)
    cases = [seed_case(engine, index) for index in range(ITERATIONS)]
    with Session() as db:
        user = db.get(User, identifier, populate_existing=True)
        token, _ = issue(db, user)
        db.commit()

    api, dispatcher, monitor = None, None, None
    samples, errors = [], []
    try:
        api = start_api(os.environ.copy())
        dispatcher = Dispatcher()
        dispatcher.start()
        monitor = ResourceMonitor(CONTAINERS, pids=child_pids(api.pid) + [api.pid], interval=RESOURCE_INTERVAL)
        monitor.start()
        with connect(f'ws://127.0.0.1:{API_PORT}/api/v1/ws', origin=ORIGIN, open_timeout=20, close_timeout=5) as socket:
            socket.send(json.dumps({'access_token': token, 'channels': ['alerts.stream', 'indicators.high_severity']}))
            hello = json.loads(socket.recv(timeout=20))
            if hello.get('status') != 'subscribed':
                raise RuntimeError('WebSocket subscription failed')
            with httpx.Client(timeout=30) as client:
                for case in cases:
                    payload = {'source': 'controlled-latency', 'external_id': case['external_id'],
                               'occurred_at': now().isoformat(), 'asset': 'controlled-latency-asset',
                               'observables': [{'type': 'ip', 'value': case['value']}], 'controlled_test': True}
                    started = time.perf_counter()
                    response = client.post(API_URL + '/api/v1/events', headers={'Authorization': 'Bearer ' + token},
                                           json=payload)
                    http_ms = (time.perf_counter() - started) * 1000
                    if response.status_code != 201:
                        errors.append({'case': case['external_id'], 'status': response.status_code,
                                       'body': response.text[:200]})
                        continue
                    deadline = time.perf_counter() + 10
                    received, received_alert_id = None, None
                    while time.perf_counter() < deadline:
                        try:
                            message = json.loads(socket.recv(timeout=deadline - time.perf_counter()))
                        except TimeoutError:
                            break
                        message_id = message.get('id')
                        # Cases run sequentially and each iteration waits for a message
                        # before posting the next event, so the next alerts.stream
                        # broadcast is necessarily this case's alert.  The alert row only
                        # exists after the dispatcher's correlation pass, so look it up
                        # by indicator + rule now and cross-check the broadcast id.
                        with Session() as db:
                            expected_alert_id = db.scalar(select(Alert.id).where(
                                Alert.indicator_id == case['indicator_id'],
                                Alert.rule_id == rule_id).order_by(Alert.created_at.desc(), Alert.id))
                        if message.get('channel') == 'alerts.stream' and message_id == expected_alert_id:
                            received, received_alert_id = time.perf_counter(), message_id
                            break
                    if received is None:
                        with Session() as db:
                            expected_alert_id = db.scalar(select(Alert.id).where(
                                Alert.indicator_id == case['indicator_id'],
                                Alert.rule_id == rule_id).order_by(Alert.created_at.desc(), Alert.id))
                        errors.append({'case': case['external_id'], 'error_type': 'timeout_waiting_for_alert',
                                       'expected_alert_id': expected_alert_id})
                        continue
                    refetch_started = time.perf_counter()
                    listing = client.get(API_URL + '/api/v1/alerts', headers={'Authorization': 'Bearer ' + token}).json()['items']
                    alert_page = 1
                    alert = next((row for row in listing if row['id'] == expected_alert_id), None)
                    # The queue endpoint returns at most 100 rows per page; keep paging so
                    # the visibility check reflects retrieval, not an arbitrary page cutoff.
                    while alert is None and alert_page < 5:
                        alert_page += 1
                        page = client.get(API_URL + '/api/v1/alerts', params={'offset': (alert_page - 1) * 100},
                                          headers={'Authorization': 'Bearer ' + token}).json()['items']
                        if not page:
                            break
                        listing.extend(page)
                        alert = next((row for row in page if row['id'] == expected_alert_id), None)
                    refetch_ms = (time.perf_counter() - refetch_started) * 1000
                    samples.append({'case': case['external_id'], 'http_ms': round(http_ms, 2),
                                    'event_to_ws_ms': round((received - started) * 1000, 2),
                                    'http_response_to_ws_ms': round((received - started) * 1000 - http_ms, 2),
                                    'ws_to_alert_refetch_ms': round(refetch_ms, 2),
                                    'alert_id': expected_alert_id, 'received_alert_id': received_alert_id,
                                    'alert_visible': alert is not None, 'alert_page': alert_page,
                                    'alert_on_first_page': alert is not None and alert_page == 1,
                                    'alert_recipient_matches': bool(alert and alert.get('recipient_id') == identifier)})
    finally:
        if monitor:
            monitor.stop()
        if dispatcher:
            dispatcher.stop()
        if api:
            api.terminate()
            api.wait(timeout=15)

    identifiers = [case['indicator_id'] for case in cases]
    feed_ids = [case['feed_id'] for case in cases]
    with engine.begin() as db:
        alert_ids = db.scalars(select(Alert.id).where(Alert.indicator_id.in_(identifiers))).all()
        db.execute(delete(Notification).where(Notification.alert_id.in_(alert_ids)))
        db.execute(delete(Alert).where(Alert.indicator_id.in_(identifiers)))
        db.execute(delete(AlertRule).where(AlertRule.id == rule_id))
        db.execute(delete(Sighting).where(Sighting.indicator_id.in_(identifiers)))
        db.execute(delete(EventObservable).where(EventObservable.event_id.in_(
            select(SecurityEvent.id).where(SecurityEvent.external_id.in_([case['external_id'] for case in cases])))))
        db.execute(delete(SecurityEvent).where(SecurityEvent.external_id.in_([case['external_id'] for case in cases])))
        db.execute(delete(Enrichment).where(Enrichment.indicator_id.in_(identifiers)))
        db.execute(delete(Outbox).where(Outbox.object_id.in_(identifiers + [rule_id] + alert_ids)))
        db.execute(delete(Provenance).where(Provenance.indicator_id.in_(identifiers)))
        db.execute(delete(Indicator).where(Indicator.id.in_(identifiers)))
        db.execute(delete(Feed).where(Feed.id.in_(feed_ids)))
        db.execute(delete(Refresh).where(Refresh.user_id == identifier))
    engine.dispose()

    def column(name):
        return [row[name] for row in samples if row.get(name) is not None]

    def stats(name):
        values = column(name)
        if not values:
            return {'count': 0}
        return {'count': len(values), 'p50': percentile(values, .50), 'p95': percentile(values, .95),
                'p99': percentile(values, .99), 'mean': round(sum(values) / len(values), 2),
                'max': round(max(values), 2)}

    result = {
        'run': RUN, 'hardware': hardware(),
        'target': {'iterations': ITERATIONS, 'requirement': 'ingest-to-UI latency target < 5000 ms'},
        'actual': {'completed': len(samples), 'errors': len(errors), 'error_samples': errors[:10],
                   'alerts_visible': sum(1 for row in samples if row['alert_visible']),
                   'alerts_on_first_page': sum(1 for row in samples if row.get('alert_on_first_page')),
                   'recipient_matched': sum(1 for row in samples if row['alert_recipient_matches'])},
        'latency_ms': {name: stats(name) for name in
                       ('http_ms', 'event_to_ws_ms', 'http_response_to_ws_ms', 'ws_to_alert_refetch_ms')},
        'samples': samples,
        'dispatcher': {'errors': len(dispatcher.errors) if dispatcher else 0,
                       'error_samples': dispatcher.errors[:10] if dispatcher else []},
        'resources': monitor.summarize(),
        'isolation': {'database': 'threatlens_test', 'redis_database': 3, 'search_index': SEARCH_INDEX,
                      'production_business_rows_touched': 0},
        'not_measured': 'Browser DOM paint is measured separately by scripts/latency_ui.mjs',
    }
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-ingest-latency.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
