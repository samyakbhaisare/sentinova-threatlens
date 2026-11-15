"""NFR-04 availability SLO + fault-injection drill (isolated test stack).

Measures steady-state API availability, scrapes the new readiness/error-budget
metric, injects an API process failure and measures recovery, and proves
readiness removes a pod with each failed dependency (PostgreSQL, Redis, search)
while liveness stays up.  Optionally probes an already-running dashboard via
``NFR_AVAILABILITY_DASHBOARD_URL``.

A 30-day production window cannot be elapsed here; the artifact states that
limit explicitly.  Use ``scripts/availability_monitor.py`` for the real window.
"""
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy.engine import make_url

from nfr_common import ensure_port_free, hardware, percentile

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr-availability-' + secrets.token_hex(4)
PORT = int(os.environ.get('NFR_AVAILABILITY_PORT', '8107'))
BAD_DEP_PORT = PORT + 1
URL = f'http://127.0.0.1:{PORT}'
STEADY_SECONDS = float(os.environ.get('NFR_AVAILABILITY_STEADY', '10'))
POST_SECONDS = float(os.environ.get('NFR_AVAILABILITY_POST', '20'))
DASHBOARD_URL = os.environ.get('NFR_AVAILABILITY_DASHBOARD_URL', '').rstrip('/')
TARGET_PERCENT = 99.5
ALLOWED_DOWNTIME_MINUTES = 30 * 24 * 60 * (1 - TARGET_PERCENT / 100)

_test_url = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test')
os.environ['DATABASE_URL'] = _test_url.render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['TEST_MODE'] = 'true'
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if _test_url.database != 'threatlens_test':
    raise SystemExit('Refusing to probe a non-test database')


def start_api(port, env):
    ensure_port_free(port)
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-{port}-api.log').open('ab')
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1',
                                '--port', str(port), '--log-level', 'warning'],
                               cwd=ROOT / 'backend', stdout=log, stderr=log, env=env)
    deadline = time.perf_counter() + 60
    while time.perf_counter() < deadline:
        if process.poll() is not None:
            break
        try:
            if httpx.get(f'http://127.0.0.1:{port}/health/live', timeout=2).status_code == 200:
                return process, time.perf_counter()
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    process.terminate()
    raise RuntimeError(f'API on {port} did not become live')


def probe(client, path, phase, base=URL):
    started = time.perf_counter()
    try:
        response = client.get(base + path, timeout=3)
        return {'phase': phase, 'path': path, 'status': response.status_code,
                'latency_ms': round((time.perf_counter() - started) * 1000, 2)}
    except httpx.HTTPError as exc:
        return {'phase': phase, 'path': path, 'status': type(exc).__name__,
                'latency_ms': round((time.perf_counter() - started) * 1000, 2)}


def dependency_failure(name, env_overrides, port):
    """Start an API with one broken dependency and prove readiness gates it."""
    env = os.environ.copy()
    env.update(env_overrides)
    process, _ = start_api(port, env)
    try:
        with httpx.Client(timeout=10) as client:
            started = time.perf_counter()
            live = client.get(f'http://127.0.0.1:{port}/health/live')
            live_ms = round((time.perf_counter() - started) * 1000, 2)
            started = time.perf_counter()
            ready = client.get(f'http://127.0.0.1:{port}/health/ready', timeout=10)
            ready_ms = round((time.perf_counter() - started) * 1000, 2)
            metrics = client.get(f'http://127.0.0.1:{port}/metrics', timeout=15)
        gauge = None
        match = re.search(r'^threatlens_readiness_up ([0-9.]+)$', metrics.text, re.MULTILINE)
        if match:
            gauge = float(match.group(1))
        dependency = re.search(rf'^threatlens_dependency_up\{{dependency="{name}"\}} ([0-9.]+)$',
                               metrics.text, re.MULTILINE)
        return {
            'dependency': name,
            'override': next(iter(env_overrides)),
            'live_status': live.status_code,
            'ready_status': ready.status_code,
            'live_latency_ms': live_ms,
            'ready_latency_ms': ready_ms,
            'readiness_gated': live.status_code == 200 and ready.status_code == 503,
            'readiness_gauge': gauge,
            'dependency_gauge': float(dependency.group(1)) if dependency else None,
        }
    finally:
        process.terminate()
        process.wait(timeout=15)


def budget(ratio):
    if ratio is None:
        return None
    used = (1 - ratio) / (1 - TARGET_PERCENT / 100)
    return {'used_fraction_of_budget': round(used, 4),
            'remaining_fraction_of_budget': round(1 - used, 4),
            'allowed_downtime_minutes': ALLOWED_DOWNTIME_MINUTES,
            'observed_downtime_minutes_for_window': None,
            'note': 'Budget arithmetic only; the elapsed 30-day window is not simulated.'}


def main():
    api, samples, dashboard_samples, recovery_ms = None, [], [], None
    try:
        api, _ = start_api(PORT, os.environ.copy())
        with httpx.Client() as client:
            deadline = time.perf_counter() + STEADY_SECONDS
            while time.perf_counter() < deadline:
                samples.extend([probe(client, '/health/live', 'steady'), probe(client, '/health/ready', 'steady')])
                if DASHBOARD_URL:
                    dashboard_samples.extend([probe(client, '/healthz', 'steady', DASHBOARD_URL),
                                              probe(client, '/', 'steady', DASHBOARD_URL)])
                time.sleep(0.25)

            failed_at = time.perf_counter()
            api.terminate()
            api.wait(timeout=15)
            time.sleep(0.5)
            samples.extend([probe(client, '/health/live', 'injected_failure'),
                            probe(client, '/health/ready', 'injected_failure')])
            api, restarted_at = start_api(PORT, os.environ.copy())
            recovery_ms = round((restarted_at - failed_at) * 1000, 2)

            deadline = time.perf_counter() + POST_SECONDS
            while time.perf_counter() < deadline:
                samples.extend([probe(client, '/health/live', 'recovered'), probe(client, '/health/ready', 'recovered')])
                if DASHBOARD_URL:
                    dashboard_samples.extend([probe(client, '/healthz', 'recovered', DASHBOARD_URL),
                                              probe(client, '/', 'recovered', DASHBOARD_URL)])
                time.sleep(0.25)

            readiness_metric = probe(client, '/metrics', 'telemetry')

        # Dependency faults: readiness must fail while liveness remains healthy.
        broken_database = _test_url.set(port=9).render_as_string(hide_password=False)
        broken_redis = os.environ['REDIS_URL'].rsplit('/', 1)[0].rsplit(':', 1)[0] + ':9/3'
        dependency_faults = [
            dependency_failure('elasticsearch', {'SEARCH_URL': 'http://127.0.0.1:9'}, BAD_DEP_PORT),
            dependency_failure('redis', {'REDIS_URL': broken_redis}, BAD_DEP_PORT + 1),
            dependency_failure('postgresql', {'DATABASE_URL': broken_database}, BAD_DEP_PORT + 2),
        ]
    finally:
        if api and api.poll() is None:
            api.terminate()
            api.wait(timeout=15)

    latencies = [row['latency_ms'] for row in samples]
    steady = [row for row in samples if row['phase'] != 'injected_failure']
    steady_ok = [row for row in steady if row['status'] == 200]
    steady_ratio = len(steady_ok) / len(steady) if steady else None
    dashboard_steady = [row for row in dashboard_samples if row['phase'] != 'injected_failure']
    dashboard_ok = [row for row in dashboard_steady if row['status'] == 200]
    result = {
        'run': RUN,
        'measured_at': datetime.now(timezone.utc).isoformat(),
        'target': {'monthly_availability_percent': TARGET_PERCENT,
                   'allowed_downtime_minutes_per_30_days': ALLOWED_DOWNTIME_MINUTES,
                   'requirement': 'NFR-04: 99.5% monthly availability for core API and dashboard'},
        'fault_injection': {
            'api_terminate_restart': {'recovery_ms': recovery_ms,
                                      'failed_probe_samples': [row for row in samples if row['phase'] == 'injected_failure']},
            'dependency_failures': dependency_faults,
        },
        'telemetry': {'metrics_endpoint': readiness_metric},
        'observed': {
            'api': {'steady_probes': len(steady), 'steady_successes': len(steady_ok),
                    'steady_availability_percent': round(steady_ratio * 100, 4) if steady_ratio is not None else None,
                    'error_budget': budget(steady_ratio)},
            'dashboard': ({'configured': True, 'url': DASHBOARD_URL,
                           'steady_probes': len(dashboard_steady), 'steady_successes': len(dashboard_ok),
                           'steady_availability_percent': round(len(dashboard_ok) / len(dashboard_steady) * 100, 4)
                           if dashboard_steady else None,
                           'error_budget': budget(len(dashboard_ok) / len(dashboard_steady) if dashboard_steady else None)}
                          if DASHBOARD_URL else {'configured': False,
                                                 'note': 'Set NFR_AVAILABILITY_DASHBOARD_URL to probe a running dashboard.'}),
            'all_probes': len(samples), 'all_successes': sum(1 for row in samples if row['status'] == 200),
            'sample_latency_ms': {'p50': percentile(latencies, .50), 'p95': percentile(latencies, .95),
                                  'max': round(max(latencies), 2) if latencies else None},
        },
        'hardware': hardware(),
        'isolation': {'database': 'threatlens_test', 'redis_database': 3,
                      'production_business_rows_touched': 0, 'production_containers_stopped': 0},
        'honest_limit': 'A short fault-injection drill cannot replace a 30-day production uptime window; '
                        'the 99.5% target, telemetry, dependency isolation and recovery are verified, '
                        'not the elapsed month. Run scripts/availability_monitor.py for the real window.',
    }
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-availability-drill.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
