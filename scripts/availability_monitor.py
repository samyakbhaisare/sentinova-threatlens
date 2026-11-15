"""Reproducible NFR-04 availability monitor.

Samples the core API (`/health/live`, `/health/ready`) and the dashboard
(`/healthz`, `/`) on a fixed interval, appends one JSON record per cycle to a
JSONL state file, and computes the trailing 30-day availability and error
budget from the recorded samples.

The monitor never invents samples. A fresh state file therefore reports
``window_complete: false`` and a short ``observed_span_hours`` until a real
30-day window has actually elapsed. Run it under a process supervisor for the
production acceptance window; a single invocation shorter than 30 days is a
drill, not a monthly SLO result.

Example (30-second probes for the full 30-day window):
    python scripts/availability_monitor.py --duration-days 30

Short verification run:
    python scripts/availability_monitor.py --duration-seconds 120 --state artifacts/verification/availability-monitor.jsonl
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = ROOT / 'artifacts' / 'verification' / 'availability-monitor.jsonl'
DEFAULT_REPORT = ROOT / 'artifacts' / 'verification' / 'availability-monitor-report.json'
TARGET = 99.5
WINDOW = timedelta(days=30)
ALLOWED_DOWNTIME_MINUTES = 30 * 24 * 60 * (1 - TARGET / 100)  # 216.0


def probe(client, url):
    started = time.perf_counter()
    try:
        response = client.get(url, timeout=5)
        return response.status_code == 200, response.status_code, round((time.perf_counter() - started) * 1000, 2)
    except httpx.HTTPError as exc:
        return False, type(exc).__name__, round((time.perf_counter() - started) * 1000, 2)


def sample(client, api_url, dashboard_url):
    api_live = probe(client, api_url + '/health/live')
    api_ready = probe(client, api_url + '/health/ready')
    dashboard_health = probe(client, dashboard_url + '/healthz')
    dashboard_root = probe(client, dashboard_url + '/')
    api_ok = api_live[0] and api_ready[0]
    dashboard_ok = dashboard_health[0] and dashboard_root[0]
    return {
        'at': datetime.now(timezone.utc).isoformat(),
        'api': {'ok': api_ok, 'live': api_live[1], 'ready': api_ready[1],
                'latency_ms': max(api_live[2], api_ready[2])},
        'dashboard': {'ok': dashboard_ok, 'healthz': dashboard_health[1], 'root': dashboard_root[1],
                      'latency_ms': max(dashboard_health[2], dashboard_root[2])},
    }


def summarize(state_path, window=WINDOW, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = now - window
    samples = []
    if state_path.exists():
        for line in state_path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                at = datetime.fromisoformat(row['at'])
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
            if at >= cutoff:
                samples.append((at, row))

    timeline = sorted(at for at, _ in samples)
    span = (timeline[-1] - timeline[0]) if len(timeline) > 1 else timedelta(0)
    report = {
        'generated_at': now.isoformat(),
        'window_days': window.days,
        'target_percent': TARGET,
        'allowed_downtime_minutes': round(ALLOWED_DOWNTIME_MINUTES, 1),
        'samples': len(samples),
        'observed_span_hours': round(span.total_seconds() / 3600, 3),
        'window_complete': span >= window,
        'state_file': str(state_path),
        'honest_limit': None if span >= window else
                        'Fewer than 30 days of real samples have been recorded; this is a partial window, not a monthly SLO result.',
    }
    for service in ('api', 'dashboard'):
        outcomes = [bool(row[service]['ok']) for _, row in samples]
        successes = sum(outcomes)
        ratio = successes / len(outcomes) if outcomes else None
        downtime = sum(1 for ok in outcomes if not ok)
        report[service] = {
            'checks': len(outcomes),
            'successes': successes,
            'failures': downtime,
            'availability_percent': round(ratio * 100, 4) if ratio is not None else None,
            'observed_target_met': (ratio >= TARGET / 100) if ratio is not None else None,
            'monthly_slo_met': ((ratio >= TARGET / 100) if span >= window else None) if ratio is not None else None,
            'error_budget_remaining_percent': round((1 - (1 - ratio) / (1 - TARGET / 100)) * 100, 2)
                                              if ratio is not None else None,
        }
    return report


def main():
    parser = argparse.ArgumentParser(description='Record and report ThreatLens monthly availability (NFR-04).')
    parser.add_argument('--api-url', default=os.environ.get('THREATLENS_API_URL', 'http://127.0.0.1:8000'))
    parser.add_argument('--dashboard-url', default=os.environ.get('THREATLENS_DASHBOARD_URL', 'http://127.0.0.1:3000'))
    parser.add_argument('--interval', type=float, default=30.0, help='seconds between samples')
    parser.add_argument('--duration-seconds', type=float, default=0.0, help='0 runs until interrupted')
    parser.add_argument('--duration-days', type=float, default=0.0)
    parser.add_argument('--state', type=Path, default=DEFAULT_STATE)
    parser.add_argument('--report', type=Path, default=DEFAULT_REPORT)
    parser.add_argument('--report-only', action='store_true', help='summarize an existing state file without probing')
    args = parser.parse_args()

    args.state.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)

    if not args.report_only:
        duration = args.duration_seconds + args.duration_days * 86400
        deadline = time.monotonic() + duration if duration else None
        with args.state.open('a', encoding='utf-8') as handle, httpx.Client() as client:
            cycles = 0
            try:
                while deadline is None or time.monotonic() < deadline:
                    row = sample(client, args.api_url.rstrip('/'), args.dashboard_url.rstrip('/'))
                    handle.write(json.dumps(row) + '\n')
                    handle.flush()
                    cycles += 1
                    print(f"{row['at']} api={'UP' if row['api']['ok'] else 'DOWN'} "
                          f"dashboard={'UP' if row['dashboard']['ok'] else 'DOWN'} "
                          f"api_ms={row['api']['latency_ms']}", flush=True)
                    if deadline is None:
                        time.sleep(args.interval)
                    else:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        time.sleep(min(args.interval, remaining))
            except KeyboardInterrupt:
                pass
        print(f'recorded {cycles} cycles to {args.state}')

    report = summarize(args.state)
    args.report.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    print('saved', args.report)
    return 0 if report['api']['observed_target_met'] is not False else 1


if __name__ == '__main__':
    sys.exit(main())
