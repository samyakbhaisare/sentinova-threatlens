"""NFR-01 / FR-20 browser verification against an isolated real API + frontend.

Seeds synthetic geo evidence in ``threatlens_test``, starts the current frontend
in dev mode and the API on a dedicated port, runs Playwright with real API
responses, and records dashboard interactive timings plus the rendered heatmap.
No production rows, containers or data are touched.
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
from sqlalchemy import delete, select

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr-ui-' + secrets.token_hex(4)
API_PORT = int(os.environ.get('NFR_UI_API_PORT', '8107'))
UI_PORT = int(os.environ.get('NFR_UI_PORT', '3100'))
os.environ['DATABASE_URL'] = os.environ['DATABASE_URL'].rsplit('/', 1)[0] + '/threatlens_test'
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['SEARCH_INDEX'] = 'threatlens_nfr_ui_' + RUN.replace('-', '_')
os.environ['TEST_MODE'] = 'true'
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if os.environ['DATABASE_URL'].rsplit('/', 1)[-1] != 'threatlens_test':
    raise SystemExit('Refusing to run browser verification against a non-test database')

from app.db import Session  # noqa: E402
from app.models import Enrichment, Feed, Indicator, Outbox, Provenance, SecurityEvent, Sighting, User, now  # noqa: E402
from app.security import hasher  # noqa: E402

EMAIL = 'nfr-ui-' + secrets.token_hex(4) + '@example.org'
PASSWORD = secrets.token_urlsafe(24)
VALUE = '9.9.9.9'
EXTERNAL = RUN + '-geo-target'


def seed():
    stamp = now()
    with Session.begin() as db:
        user = User(name='Controlled NFR UI executive', email=EMAIL, password_hash=hasher.hash(PASSWORD), role='executive')
        db.add(user)
        db.flush()
        feed = Feed(name=RUN.upper() + ' UI FEED', adapter='json', url='internal', reliability=90,
                    enabled=False, ttl_days=30)
        db.add(feed)
        db.flush()
        indicator = Indicator(type='ip', value=VALUE, score=80, confidence=90, reputation=87, tlp='clear',
                              status='active', category='malware', expires_at=stamp + timedelta(days=30),
                              first_seen=stamp, last_seen=stamp)
        db.add(indicator)
        db.flush()
        db.add(Provenance(indicator_id=indicator.id, feed_id=feed.id, confidence=90, tlp='clear', reference=RUN))
        db.add(Enrichment(indicator_id=indicator.id, provider='ipwhois', expires_at=stamp + timedelta(hours=1), data={
            'provider': 'ipwhois', 'status': 'ok', 'observed_at': stamp.isoformat(),
            'latitude': 37.7749, 'longitude': -122.4194, 'country': 'US',
            'asn': 15169, 'owner': 'Controlled Cloud'}))
        event = SecurityEvent(source='controlled-ui-ipam', external_id=EXTERNAL, occurred_at=stamp,
                              asset='controlled-ui-host', observables=[{'type': 'ip', 'value': VALUE}],
                              controlled_test=True, digest='controlled-ui-digest', details={'target_geo': {
                                  'latitude': 52.52, 'longitude': 13.405, 'country': 'DE',
                                  'source': 'controlled IPAM telemetry', 'observed_at': stamp.isoformat()}})
        db.add(event)
        db.flush()
        db.add(Sighting(indicator_id=indicator.id, event_id=event.id))
        return user.id, feed.id, indicator.id, event.id


def start_api():
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-api.log').open('ab')
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
                                '--port', str(API_PORT), '--log-level', 'warning'],
                               cwd=ROOT / 'backend', stdout=log, stderr=log, env=os.environ.copy())
    for _ in range(120):
        try:
            if httpx.get(f'http://127.0.0.1:{API_PORT}/health/live', timeout=2).status_code == 200:
                return process
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    process.terminate()
    raise RuntimeError('NFR UI API did not become ready')


def start_frontend():
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-frontend.log').open('ab')
    command = ['cmd', '/c', 'npm.cmd', 'run', 'dev', '--', '--hostname', '127.0.0.1', '--port', str(UI_PORT)]
    process = subprocess.Popen(command, cwd=ROOT / 'frontend', stdout=log, stderr=log, env=os.environ.copy())
    for _ in range(240):
        try:
            if httpx.get(f'http://127.0.0.1:{UI_PORT}/', timeout=2).status_code == 200:
                return process
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    process.terminate()
    raise RuntimeError('NFR UI frontend did not become ready')


def terminate(process):
    if not process:
        return
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
    else:
        process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()


def main():
    user_id, feed_id, indicator_id, event_id = seed()
    api = frontend = None
    try:
        api = start_api()
        frontend = start_frontend()
        env = os.environ.copy()
        env.update({'UI_URL': f'http://127.0.0.1:{UI_PORT}',
                    'E2E_API_URL': f'http://127.0.0.1:{API_PORT}',
                    'E2E_EMAIL': EMAIL, 'E2E_PASSWORD': PASSWORD, 'NFR_UI_RUN': RUN,
                    'E2E_BROWSER_PATH': os.environ.get('E2E_BROWSER_PATH', '')})
        command = ['cmd', '/c', 'npx.cmd', 'playwright', 'test', 'e2e/nfr-ui.spec.ts',
                   '--config=playwright.config.ts']
        result = subprocess.run(command, cwd=ROOT / 'frontend', env=env, capture_output=True, text=True,
                                encoding='utf-8', errors='replace')
        log = ROOT / 'artifacts' / 'verification' / f'{RUN}-playwright.log'
        log.write_text(result.stdout + "\n---STDERR---\n" + result.stderr, encoding='utf-8')
        print(result.stdout[-3000:].encode('ascii', 'replace').decode('ascii'))
        if result.stderr:
            print(result.stderr[-2000:].encode('ascii', 'replace').decode('ascii'), file=sys.stderr)
        if result.returncode != 0:
            raise SystemExit(result.returncode)
    finally:
        terminate(frontend)
        terminate(api)
        with Session.begin() as db:
            user = db.get(User, user_id)
            if user:
                user.enabled = False
                user.token_version += 1
            db.execute(delete(Sighting).where(Sighting.indicator_id == indicator_id))
            db.execute(delete(Enrichment).where(Enrichment.indicator_id == indicator_id))
            db.execute(delete(Outbox).where(Outbox.object_id.in_([indicator_id, event_id])))
            db.execute(delete(Provenance).where(Provenance.indicator_id == indicator_id))
            db.execute(delete(Indicator).where(Indicator.id == indicator_id))
            db.execute(delete(SecurityEvent).where(SecurityEvent.id == event_id))
            db.execute(delete(Feed).where(Feed.id == feed_id))
    artifact = ROOT / 'artifacts' / 'verification' / f'{RUN}-ui-latency.json'
    if artifact.exists():
        print('artifact', artifact)
        print(json.dumps(json.loads(artifact.read_text()), indent=2)[:4000])


if __name__ == '__main__':
    main()
