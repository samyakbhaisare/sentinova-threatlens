"""Authenticated WebSocket fan-out at 200 concurrent connections (NFR-02/03).

The API is started against ``threatlens_test`` and Redis logical database 3.
Each client subscribes with a real JWT, then the harness publishes real Redis
messages on the application event channel and measures server-to-client delivery.
No production service or production Redis database is used.
"""
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import redis
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

RUN = 'nfr-ws-' + secrets.token_hex(4)
SEARCH_INDEX = 'threatlens_nfr_' + RUN.replace('-', '_')
API_PORT = int(os.environ.get('NFR_WS_PORT', '8104'))
API_URL = f'http://127.0.0.1:{API_PORT}'
CLIENTS = int(os.environ.get('NFR_WS_CLIENTS', '200'))
MESSAGES = int(os.environ.get('NFR_WS_MESSAGES', '20'))
RESOURCE_INTERVAL = int(os.environ.get('NFR_RESOURCE_INTERVAL', '10'))
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
from app.models import Refresh, User, uid  # noqa: E402
from app.security import hasher, issue  # noqa: E402
from app.search import event_channel  # noqa: E402


def ensure_user(engine):
    email = 'nfr-websocket@example.org'
    password = secrets.token_urlsafe(24)
    with engine.begin() as db:
        identifier = db.scalar(select(User.id).where(User.email == email))
        values = dict(name='CONTROLLED WS BENCHMARK', role='administrator',
                      password_hash=hasher.hash(password), enabled=True, token_version=1, layout=[])
        if identifier:
            db.execute(update(User).where(User.id == identifier).values(**values))
        else:
            identifier = uid()
            db.execute(insert(User), [dict(id=identifier, email=email, **values)])
    return identifier


def start_api(env):
    ensure_port_free(API_PORT)
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-api.log').open('ab')
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
                                '--port', str(API_PORT), '--log-level', 'warning'],
                               cwd=ROOT / 'backend', stdout=log, stderr=log, env=env)
    for _ in range(80):
        if process.poll() is not None:
            break
        try:
            if httpx.get(API_URL + '/health/live', timeout=1).status_code == 200:
                return process
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    process.terminate()
    raise RuntimeError('WebSocket benchmark API did not become ready')


def main():
    settings.cache_clear()
    engine = create_engine(os.environ['DATABASE_URL'])
    from app.db import Base
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    user_id = ensure_user(engine)
    with Session() as db:
        user = db.get(User, user_id, populate_existing=True)
        token, _ = issue(db, user)
        db.commit()

    api, monitor = None, None
    clients, lock = [], threading.Lock()
    ready = threading.Event()
    stop = threading.Event()
    connect_latencies, subscribe_latencies, delivery_latencies = [], [], []
    received_counts, failures = [], []
    teardown = {'count': 0}
    subscribed = {'count': 0}
    threads = []

    def worker(position):
        state = {'connected': False, 'subscribed': False, 'messages': []}
        try:
            started = time.perf_counter()
            with connect(f'ws://127.0.0.1:{API_PORT}/api/v1/ws', origin=ORIGIN, open_timeout=20,
                         close_timeout=5, max_size=2 ** 20) as socket:
                state['connected'] = True
                connect_latencies.append((time.perf_counter() - started) * 1000)
                hello = {'access_token': token, 'channels': ['alerts.stream', 'indicators.high_severity']}
                sent = time.perf_counter()
                socket.send(json.dumps(hello))
                while True:
                    message = json.loads(socket.recv(timeout=20))
                    if message.get('status') == 'subscribed':
                        state['subscribed'] = True
                        subscribe_latencies.append((time.perf_counter() - sent) * 1000)
                        with lock:
                            subscribed['count'] += 1
                            if subscribed['count'] == CLIENTS:
                                ready.set()
                        break
                while not stop.is_set():
                    try:
                        message = json.loads(socket.recv(timeout=1))
                    except TimeoutError:
                        continue
                    state['messages'].append((time.perf_counter(), message))
        except Exception as exc:  # noqa: BLE001 - failures are measured, never hidden
            if stop.is_set() and type(exc).__name__ in ('ConnectionClosedError', 'ConnectionClosedOK'):
                with lock:
                    teardown['count'] += 1  # harness shutdown, not a client failure
            else:
                with lock:
                    failures.append({'client': position, 'error_type': type(exc).__name__, 'detail': str(exc)[:200]})
        finally:
            with lock:
                clients.append(state)

    try:
        api = start_api(os.environ.copy())
        monitor = ResourceMonitor(CONTAINERS, pids=child_pids(api.pid) + [api.pid], interval=RESOURCE_INTERVAL)
        monitor.start()

        threads = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(CLIENTS)]
        for thread in threads:
            thread.start()
        if not ready.wait(timeout=90):
            raise RuntimeError(f'Only {subscribed["count"]}/{CLIENTS} clients subscribed')

        cache = redis.Redis.from_url(os.environ['REDIS_URL'], decode_responses=True)
        channel = event_channel()
        publish_started = time.perf_counter()
        for index in range(MESSAGES):
            cache.publish(channel, json.dumps({'channel': 'alerts.stream', 'id': f'broadcast-{index}'}))
            time.sleep(0.05)
        deadline = publish_started + 25
        while time.perf_counter() < deadline:
            with lock:
                if clients and all(len(state['messages']) >= MESSAGES for state in clients):
                    break
            time.sleep(0.1)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=10)
        if monitor:
            monitor.stop()
        if api:
            api.terminate()
            api.wait(timeout=15)

    for state in clients:
        timestamps = [row[0] for row in state['messages']]
        received_counts.append(len(timestamps))
        if timestamps:
            delivery_latencies.extend([(stamp - publish_started) * 1000 for stamp in timestamps[:1]])
    with Session() as db:
        db.execute(delete(Refresh).where(Refresh.user_id == user_id))
        db.commit()
    engine.dispose()

    result = {
        'run': RUN, 'hardware': hardware(),
        'target': {'concurrent_websocket_clients': CLIENTS, 'broadcast_messages': MESSAGES},
        'actual': {'connected': len(connect_latencies), 'subscribed': len(subscribe_latencies),
                   'failed_connections': len(failures), 'failure_samples': failures[:10],
                   'harness_teardown_disconnects': teardown['count'],
                   'clients_receiving_at_least_one': sum(1 for count in received_counts if count),
                   'clients_receiving_all_messages': sum(1 for count in received_counts if count >= MESSAGES),
                   'messages_expected_per_client': MESSAGES,
                   'note': 'clients connecting after all publishes were delivered are excluded from delivery stats'},
        'latency_ms': {'connect': {'p50': percentile(connect_latencies, .50), 'p95': percentile(connect_latencies, .95),
                                   'p99': percentile(connect_latencies, .99)},
                       'subscribe': {'p50': percentile(subscribe_latencies, .50), 'p95': percentile(subscribe_latencies, .95),
                                     'p99': percentile(subscribe_latencies, .99)},
                       'first_broadcast_delivery': {'p50': percentile(delivery_latencies, .50),
                                                    'p95': percentile(delivery_latencies, .95),
                                                    'p99': percentile(delivery_latencies, .99),
                                                    'max': round(max(delivery_latencies), 2) if delivery_latencies else None}},
        'resources': monitor.summarize(),
        'isolation': {'database': 'threatlens_test', 'redis_database': 3,
                      'production_business_rows_touched': 0},
    }
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-websocket-concurrency.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
