"""NFR-10 live observability proof against the current API source.

Starts the real API on an isolated port, seeds service heartbeats in an
isolated Redis database, scrapes Prometheus metrics and reads the structured
JSON request log.  No production service or database is touched.
"""
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr-observability-' + secrets.token_hex(4)
PORT = int(os.environ.get('NFR_OBSERVABILITY_PORT', '8108'))
URL = f'http://127.0.0.1:{PORT}'
os.environ['DATABASE_URL'] = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test').render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['TEST_MODE'] = 'true'
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if make_url(os.environ['DATABASE_URL']).database != 'threatlens_test':
    raise SystemExit('Refusing to run observability proof against a non-test database')

import redis  # noqa: E402


def main():
    log_path = ROOT / 'artifacts' / 'verification' / f'{RUN}-api.log'
    log = log_path.open('ab')
    process = subprocess.Popen(
        [sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
         '--port', str(PORT), '--log-level', 'warning'],
        cwd=ROOT / 'backend', stdout=log, stderr=log, env=os.environ.copy())
    result = {'run': RUN, 'measured_at': datetime.now(timezone.utc).isoformat(),
              'requirement': 'NFR-10: structured logs, per-service metrics and health endpoints',
              'isolation': {'database': 'threatlens_test', 'redis_database': 3,
                            'production_rows_touched': 0}}
    try:
        deadline = time.perf_counter() + 90
        while time.perf_counter() < deadline:
            try:
                if httpx.get(URL + '/health/live', timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError('API did not become live')

        cache = redis.Redis.from_url(os.environ['REDIS_URL'], decode_responses=True)
        stamp = datetime.now(timezone.utc).isoformat()
        cache.set('health:dispatcher', stamp)
        cache.set('health:scheduler', stamp)

        scrape = httpx.get(URL + '/metrics', timeout=15)
        body = scrape.text
        expected = [
            'threatlens_service_heartbeat_timestamp_seconds{service="dispatcher"}',
            'threatlens_service_heartbeat_timestamp_seconds{service="scheduler"}',
            'threatlens_dependency_up{dependency="postgresql"} 1',
            'threatlens_dependency_up{dependency="redis"} 1',
            'threatlens_dependency_up{dependency="elasticsearch"} 1',
            'threatlens_outbox_pending',
            'threatlens_requests_total',
        ]
        heartbeat_lines = [line for line in body.splitlines()
                           if line.startswith('threatlens_service_heartbeat_timestamp_seconds')]
        result['metrics'] = {
            'url': URL + '/metrics', 'status': scrape.status_code,
            'content_type': scrape.headers.get('content-type'),
            'checks': {item: item in body for item in expected},
            'heartbeats': heartbeat_lines,
            'heartbeat_values_nonzero': all(
                float(line.rsplit(' ', 1)[1]) > 0 for line in heartbeat_lines),
        }
        result['health'] = {
            path: {'status': httpx.get(URL + path, timeout=5).status_code,
                   'body': httpx.get(URL + path, timeout=5).json()}
            for path in ('/health/live', '/health/ready')
        }

        time.sleep(0.5)
        lines = [line for line in log_path.read_text(encoding='utf-8', errors='replace').splitlines()
                 if line.startswith('{')]
        requests = []
        for line in lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get('service') == 'threatlens.api':
                requests.append(payload)
        result['structured_logs'] = {
            'path': str(log_path.relative_to(ROOT)),
            'json_lines': len(lines), 'api_lines': len(requests),
            'all_have_timestamp_level_service_message': all(
                {'timestamp', 'level', 'service', 'message'} <= set(row) for row in requests),
            'sample': requests[-3:],
            'correlation_ids_present': all(
                'correlation_id' in json.loads(row['message']) for row in requests
                if row['message'].startswith('{')),
        }
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()

    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-observability.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)
    ok = (result['metrics']['status'] == 200
          and all(result['metrics']['checks'].values())
          and result['metrics']['heartbeat_values_nonzero']
          and result['health']['/health/live']['status'] == 200
          and result['health']['/health/ready']['status'] == 200
          and result['structured_logs']['json_lines'] > 0
          and result['structured_logs']['all_have_timestamp_level_service_message']
          and result['structured_logs']['correlation_ids_present'])
    if not ok:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
