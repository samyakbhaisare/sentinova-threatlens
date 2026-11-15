"""Sustained ingestion benchmark (PRD NFR-01 / NFR-03 target: 50,000 events/hour).

This harness deliberately runs for a full wall-clock window instead of
multiplying a short burst.  It writes only to the isolated ``threatlens_test``
database and to an isolated search index.  Synthetic rows are removed afterwards;
append-only audit evidence stays in the isolated test database by design.

Usage (full one-hour 50k/h run):
    .venv-resume\\Scripts\\python.exe scripts\\nfr_sustained.py

Shorter diagnostic run:
    NFR_SUSTAINED_SECONDS=600 NFR_SUSTAINED_PER_HOUR=50000 ... python scripts\\nfr_sustained.py
"""
import json
import os
import secrets
import statistics
import sys
import time
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, delete, func, insert, select, text
from sqlalchemy.engine import make_url

from nfr_common import ResourceMonitor, hardware, percentile
ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

RUN = 'nfr-sustained-' + secrets.token_hex(4)
SEARCH_INDEX = 'threatlens_nfr_' + RUN.replace('-', '_')
PER_HOUR = int(os.environ.get('NFR_SUSTAINED_PER_HOUR', '50000'))
SECONDS = int(os.environ.get('NFR_SUSTAINED_SECONDS', '3600'))
TARGET = max(1, round(PER_HOUR / 3600 * SECONDS))
COMMIT_EVERY = int(os.environ.get('NFR_SUSTAINED_COMMIT_EVERY', '100'))
RESOURCE_INTERVAL = int(os.environ.get('NFR_RESOURCE_INTERVAL', '15'))
CONTAINERS = os.environ.get('NFR_CONTAINERS', 'sentinova-threatlens-postgres-1,sentinova-threatlens-redis-1').split(',')

_test_url = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test')
os.environ['DATABASE_URL'] = _test_url.render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['SEARCH_INDEX'] = SEARCH_INDEX
os.environ['TEST_MODE'] = 'true'
os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
if _test_url.database != 'threatlens_test':
    raise SystemExit('Refusing to benchmark against a non-test database')

from app.correlation import correlate  # noqa: E402
from app.db import Session  # noqa: E402
from app.intelligence import ingest  # noqa: E402
from app.models import Enrichment, Feed, Indicator, Outbox, Provenance, now, uid  # noqa: E402


def database_size(engine):
    with engine.connect() as connection:
        return connection.scalar(text("SELECT pg_database_size(current_database())"))


def batch_delete(engine, model, column, identifiers, size=1000):
    with engine.begin() as db:
        for start in range(0, len(identifiers), size):
            db.execute(delete(model).where(column.in_(identifiers[start:start + size])))


def main():
    engine = create_engine(os.environ['DATABASE_URL'])
    from app.db import Base
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    artifacts = ROOT / 'artifacts' / 'verification'
    artifacts.mkdir(parents=True, exist_ok=True)

    feed_id = uid()
    stamp = now()
    with engine.begin() as db:
        db.execute(insert(Feed), [dict(id=feed_id, name=RUN.upper() + ' SUSTAINED INGEST', adapter='json',
                                       url='internal', secret_ref='', interval_seconds=3600, ttl_days=30,
                                       enabled=False, next_poll=stamp, ingested=0, rejected=0, reliability=60)])
    size_before = database_size(engine)
    monitor = ResourceMonitor(CONTAINERS, interval=RESOURCE_INTERVAL)
    monitor.start()

    latencies, commit_latencies, minute_buckets = [], [], []
    errors = []
    created = []
    started = time.perf_counter()
    minute_start_count = 0
    next_minute = 60.0
    interval = 3600.0 / PER_HOUR
    next_deadline = started
    connection = engine.connect()
    db = Session(bind=connection, expire_on_commit=False)
    try:
        feed = db.get(Feed, feed_id)
        for index in range(TARGET):
            value = f'2001:db8:3:{RUN[14:18]}:{RUN[18:22]}::{index:x}'
            record = {'type': 'ip', 'value': value, 'confidence': 60, 'category': 'benchmark',
                      'reference': RUN}
            record_started = time.perf_counter()
            try:
                with db.begin_nested():
                    indicator = ingest(db, feed, record)
                    correlate(db, indicator=indicator)
                created.append(indicator.id)
            except Exception as exc:  # noqa: BLE001 - recorded, never hidden
                errors.append({'ordinal': index, 'error_type': type(exc).__name__})
            latencies.append((time.perf_counter() - record_started) * 1000)
            if (index + 1) % COMMIT_EVERY == 0 or index + 1 == TARGET:
                commit_started = time.perf_counter()
                db.commit()
                commit_latencies.append((time.perf_counter() - commit_started) * 1000)
            elapsed = time.perf_counter() - started
            if elapsed >= next_minute:
                minute_buckets.append({'minute': len(minute_buckets) + 1,
                                       'records': len(created) - minute_start_count,
                                       'elapsed_seconds': round(elapsed, 1)})
                minute_start_count = len(created)
                next_minute += 60.0
            next_deadline += interval
            sleep_for = next_deadline - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
        feed = db.get(Feed, feed_id)
        feed.last_success, feed.ingested = now(), len(created)
        db.commit()
    finally:
        db.close()
        connection.close()
        monitor.stop()

    duration = time.perf_counter() - started
    with engine.connect() as db:
        persisted = db.scalar(select(func.count()).select_from(Provenance).where(Provenance.feed_id == feed_id))
        pending = db.scalar(select(func.count()).select_from(Outbox).where(Outbox.object_id.in_(created)).where(Outbox.delivered.is_(False))) if created else 0
        audit_rows = db.scalar(text("SELECT count(*) FROM audit_log WHERE data->'data'->>'feed_id' = :feed"), {'feed': feed_id})
    size_after = database_size(engine)
    cleanup_started = time.perf_counter()
    if created:
        batch_delete(engine, Enrichment, Enrichment.indicator_id, created)
        batch_delete(engine, Outbox, Outbox.object_id, created)
        batch_delete(engine, Provenance, Provenance.indicator_id, created)
        batch_delete(engine, Indicator, Indicator.id, created)
    batch_delete(engine, Feed, Feed.id, [feed_id])
    cleanup_seconds = time.perf_counter() - cleanup_started
    size_after_cleanup = database_size(engine)
    result = {
        'run': RUN, 'hardware': hardware(),
        'target': {'events_per_hour': PER_HOUR, 'duration_seconds': SECONDS, 'target_records': TARGET},
        'actual': {'duration_seconds': round(duration, 2), 'records_attempted': TARGET,
                   'records_created': len(created), 'records_persisted': persisted,
                   'errors': len(errors), 'error_samples': errors[:10],
                   'effective_records_per_second': round(len(created) / duration, 3),
                   'effective_events_per_hour': round(len(created) / duration * 3600, 1)},
        'latency_ms': {'per_record_p50': percentile(latencies, .50), 'per_record_p95': percentile(latencies, .95),
                       'per_record_p99': percentile(latencies, .99),
                       'per_record_mean': round(statistics.fmean(latencies), 3) if latencies else None,
                       'per_record_max': round(max(latencies), 3) if latencies else None,
                       'commit_p95': percentile(commit_latencies, .95),
                       'commit_p99': percentile(commit_latencies, .99)},
        'per_minute': minute_buckets,
        'resources': monitor.summarize(),
        'database': {'size_before_bytes': size_before, 'size_after_bytes': size_after,
                     'growth_bytes': size_after - size_before,
                     'size_after_cleanup_bytes': size_after_cleanup,
                     'cleanup_seconds': round(cleanup_seconds, 2),
                     'pending_outbox_rows_created': pending,
                     'audit_rows_retained': audit_rows},
        'cleanup': {'synthetic_business_rows_removed': True,
                    'append_only_evidence_retained': ['audit_log']},
        'isolation': {'database': 'threatlens_test', 'redis_database': 3, 'search_index': SEARCH_INDEX,
                      'production_business_rows_touched': 0},
    }
    output = artifacts / f'{RUN}-sustained-ingest.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
