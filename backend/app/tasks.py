import hashlib
import json
from datetime import timedelta, timezone

import redis
from celery import Celery
from celery.signals import setup_logging
from sqlalchemy import func, or_, select, update

from .config import settings
from .correlation import correlate
from .db import Session
from .enrichment import enrich
from .feeds import fetch, poll
from .intelligence import ingest
from .models import Alert, Feed, Indicator, Outbox, ReferenceSync, Report, SecurityEvent, now
from .observability import configure
from .reporting import ReportPolicyError, generate, report_path
from .security import audit
from .retry import DeferredRequest
from .search import event_channel, write_documents
from .attack import REFERENCE_URL, synchronize
from .risk import capture as capture_risk
from .bulk_exports import generate_export, recover_expired

config = settings()
celery = Celery('threatlens', broker=config.redis_url, backend=config.redis_url)
celery.conf.update(task_acks_late=True, task_reject_on_worker_lost=True, worker_prefetch_multiplier=1,
    task_routes={'app.tasks.dispatch': {'queue': 'maintenance'}, 'app.tasks.schedule': {'queue': 'maintenance'},
                 'app.tasks.expire': {'queue': 'maintenance'}, 'app.tasks.poll_feed': {'queue': 'ingestion'},
                 'app.tasks.enrich_indicator': {'queue': 'operations'}, 'app.tasks.report_generate': {'queue': 'operations'},
                 'app.tasks.reference_sync': {'queue': 'operations'}, 'app.tasks.risk_snapshot': {'queue': 'maintenance'},
                 'app.tasks.export_generate': {'queue': 'operations'}},
    beat_schedule={'dispatch': {'task': 'app.tasks.dispatch', 'schedule': 1.0},
                   'schedule': {'task': 'app.tasks.schedule', 'schedule': 30.0},
                   'expiry': {'task': 'app.tasks.expire', 'schedule': 60.0}})
logger = configure('threatlens.worker')


@setup_logging.connect
def structured_logging(**_kwargs):
    """Emit Celery worker/scheduler/beat logs as JSON instead of plain text."""
    configure('celery')
    configure('threatlens.worker')


def projection(db, row):
    from .models import Provenance
    if isinstance(row, Indicator):
        return {'id': row.id, 'kind': 'indicator', 'value': row.value, 'type': row.type, 'score': row.score,
                'status': row.status, 'tlp': row.tlp, 'tags': row.tags, 'techniques': row.techniques, 'category': row.category,
                'sources': list(db.scalars(select(Provenance.feed_id).where(Provenance.indicator_id == row.id))),
                'notes': row.notes, 'created_at': row.created_at.isoformat()}
    return {'id': row.id, 'kind': 'event', 'value': row.asset, 'observables': row.observables,
            'source': row.source, 'controlled_test': row.controlled_test, 'details': row.details,
            'details_text': json.dumps(row.details, sort_keys=True), 'created_at': row.created_at.isoformat()}


@celery.task
def dispatch():
    cache = redis.Redis.from_url(config.redis_url, socket_connect_timeout=2, socket_timeout=2)
    with Session.begin() as db:
        rows = db.scalars(select(Outbox).where(Outbox.delivered.is_(False)).order_by(Outbox.created_at).limit(200).with_for_update(skip_locked=True)).all()
        documents = {}
        messages, commands = [], []
        for row in rows:
            if row.topic in ('indicators', 'events'):
                model = Indicator if row.topic == 'indicators' else SecurityEvent
                obj = db.get(model, row.object_id)
                if obj:
                    documents[f'{row.topic}-{obj.id}'] = projection(db, obj)
                    if isinstance(obj, Indicator) and obj.status == 'active' and obj.score >= 70:
                        messages.append({'channel': 'indicators.high_severity', 'id': obj.id})
            elif row.topic == 'feed.poll':
                commands.append((poll_feed, row.object_id))
            elif row.topic == 'report.generate':
                commands.append((report_generate, row.object_id))
            elif row.topic == 'indicator.enrich':
                commands.append((enrich_indicator, row.object_id))
            elif row.topic == 'attack.sync':
                commands.append((reference_sync, row.object_id))
            elif row.topic == 'risk.capture':
                commands.append((risk_snapshot, row.object_id))
            elif row.topic == 'export.generate':
                commands.append((export_generate, row.object_id))
            else:
                payload = {'channel': row.topic, 'id': row.object_id}
                if row.topic == 'alerts.stream':
                    alert = db.get(Alert, row.object_id)
                    payload['recipient_id'] = alert.recipient_id if alert else None
                messages.append(payload)
        write_documents(documents)
        for task, identifier in commands:
            task.delay(identifier)
        for message in messages:
            cache.publish(event_channel(), json.dumps(message))
        for row in rows:
            row.delivered = True
    cache.setex('health:dispatcher', 90, now().isoformat())


@celery.task
def schedule():
    with Session.begin() as db:
        capture_risk(db)
        recover_expired(db)
        recover_reports(db)
        latest_reference = db.scalar(select(ReferenceSync).order_by(ReferenceSync.created_at.desc()).limit(1))
        reference_time = latest_reference.created_at.replace(tzinfo=timezone.utc) if latest_reference and latest_reference.created_at.tzinfo is None else latest_reference.created_at if latest_reference else None
        if reference_time is None or reference_time < now() - timedelta(days=7):
            reference = ReferenceSync(source_url=REFERENCE_URL)
            db.add(reference); db.flush()
            db.add(Outbox(topic='attack.sync', object_id=reference.id))
            audit(db, None, 'attack.sync_scheduled', reference.id)
        for feed in db.scalars(select(Feed).where(Feed.enabled.is_(True), Feed.next_poll <= now()).with_for_update(skip_locked=True)):
            db.add(Outbox(topic='feed.poll', object_id=feed.id))
            feed.next_poll = now() + timedelta(seconds=feed.interval_seconds)
        for report in db.scalars(select(Report).where(Report.schedule_hours.is_not(None), Report.next_run <= now()).with_for_update(skip_locked=True)):
            child = Report(owner_id=report.owner_id, title=report.title, incident_id=report.incident_id, tlp=report.tlp)
            db.add(child)
            db.flush()
            db.add(Outbox(topic='report.generate', object_id=child.id))
            report.next_run = now() + timedelta(hours=report.schedule_hours)
            audit(db, None, 'report.scheduled', child.id)
    redis.Redis.from_url(config.redis_url).setex('health:scheduler', 90, now().isoformat())


@celery.task(bind=True, max_retries=4)
def poll_feed(self, identifier):
    cache = redis.Redis.from_url(config.redis_url)
    lock = cache.lock('feed-lock:' + identifier, timeout=900, blocking_timeout=0)
    if not lock.acquire(blocking=False):
        return
    try:
        with Session() as db:
            feed = db.get(Feed, identifier)
            if not feed or not feed.enabled:
                return
            count, rejected = 0, 0
            for record in poll(feed):
                try:
                    with db.begin_nested():
                        ioc = ingest(db, feed, record)
                        correlate(db, indicator=ioc)
                    count += 1
                except (ValueError, KeyError, TypeError) as exc:
                    rejected += 1
                    audit(db, None, 'feed.record_rejected', identifier, {'ordinal': count + rejected, 'error_type': type(exc).__name__})
                if (count + rejected) % 100 == 0:
                    db.commit()
            feed.last_success, feed.error, feed.ingested, feed.rejected = now(), None, count, rejected
            audit(db, None, 'feed.polled', feed.id, {'accepted': count, 'rejected': rejected})
            db.add(Outbox(topic='system.health', object_id=feed.id))
            db.commit()
    except Exception as exc:
        with Session.begin() as db:
            feed = db.get(Feed, identifier)
            feed.last_failure, feed.error = now(), type(exc).__name__
            audit(db, None, 'feed.failed', identifier, {'error_type': type(exc).__name__})
        logger.error(json.dumps({'event': 'feed_failure', 'feed_id': identifier, 'error_type': type(exc).__name__}))
        delay = exc.seconds if isinstance(exc, DeferredRequest) else min(900, 30 * 2 ** self.request.retries)
        raise self.retry(exc=RuntimeError(type(exc).__name__), countdown=delay)
    finally:
        if lock.owned():
            lock.release()


@celery.task
def expire():
    with Session.begin() as db:
        for ioc in db.scalars(select(Indicator).where(Indicator.status == 'active', Indicator.expires_at <= now()).limit(5000).with_for_update(skip_locked=True)):
            ioc.status = 'expired'
            db.add(Outbox(topic='indicators', object_id=ioc.id))
            audit(db, None, 'indicator.expired', ioc.id)


@celery.task(bind=True, max_retries=8)
def enrich_indicator(self, identifier):
    deferred = []
    with Session.begin() as db:
        # Classification must not change while its value is sent to a provider.
        indicator = db.scalar(select(Indicator).where(Indicator.id == identifier).with_for_update())
        if indicator:
            results = enrich(db, indicator)
            correlate(db, indicator=indicator)
            audit(db, None, 'indicator.enriched', identifier, {'providers': [{k: r[k] for k in ('provider', 'status')} for r in results]})
            deferred = [r['retry_after'] for r in results if r['status'] == 'deferred']
    if deferred:
        raise self.retry(countdown=max(deferred), exc=RuntimeError('Provider backoff; persisted results remain available'))


@celery.task
def report_generate(identifier):
    claimed = False
    with Session.begin() as db:
        claimed = db.execute(update(Report).where(Report.id == identifier, Report.state.in_(['queued', 'failed']), Report.attempts < 3).values(
            state='running', attempts=Report.attempts + 1, lease_until=now() + timedelta(minutes=10), error=None)).rowcount == 1
    if not claimed:
        # A worker that died mid-generation leaves a running row behind. Only an
        # expired lease may be reclaimed, and only while attempts remain.
        with Session.begin() as db:
            claimed = db.execute(update(Report).where(Report.id == identifier, Report.state == 'running', Report.attempts < 3,
                or_(Report.lease_until.is_(None), Report.lease_until <= now())).values(
                attempts=Report.attempts + 1, lease_until=now() + timedelta(minutes=10))).rowcount == 1
    if not claimed:
        return
    try:
        with Session.begin() as db:
            report = db.scalar(select(Report).where(Report.id == identifier).with_for_update())
            if report is None or report.state == 'cancelled':
                return
            classification = generate(db, report)
            path = report_path(identifier)
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    digest.update(chunk)
            report.state, report.error = 'ready', None
            report.checksum, report.artifact_bytes = digest.hexdigest(), path.stat().st_size
            report.ready_at, report.lease_until = now(), None
            audit(db, None, 'report.generated', identifier, {**classification, 'sha256': report.checksum,
                'bytes': report.artifact_bytes, 'attempts': report.attempts})
    except Exception as exc:
        with Session.begin() as db:
            report = db.scalar(select(Report).where(Report.id == identifier).with_for_update())
            if report is not None and report.state != 'cancelled':
                report.state = 'failed'
                report.error = str(exc) if isinstance(exc, ReportPolicyError) else type(exc).__name__
                report.lease_until = None
                audit(db, None, 'report.failed', identifier, {'error_type': type(exc).__name__, 'attempts': report.attempts})


def recover_reports(db):
    """Requeue reports whose lease expired or whose task message was lost."""
    recovered = 0
    stale = db.scalars(select(Report).where(Report.state == 'running', or_(Report.lease_until.is_(None), Report.lease_until <= now()))
        .limit(100).with_for_update(skip_locked=True).execution_options(populate_existing=True)).all()
    for report in stale:
        report.lease_until = None
        if report.attempts >= 3:
            report.state, report.error = 'failed', 'lease_retry_limit'
        else:
            report.state = 'queued'
            db.add(Outbox(topic='report.generate', object_id=report.id))
        audit(db, None, 'report.lease_recovered', report.id, {'attempts': report.attempts, 'state': report.state})
        recovered += 1
    queued = db.scalars(select(Report).where(Report.state == 'queued', Report.id.not_in([report.id for report in stale]),
        Report.created_at <= now() - timedelta(seconds=60), or_(Report.lease_until.is_(None), Report.lease_until <= now()), Report.attempts < 3)
        .limit(100).with_for_update(skip_locked=True)).all()
    for report in queued:
        if db.scalar(select(func.count()).select_from(Outbox).where(Outbox.topic == 'report.generate', Outbox.object_id == report.id, Outbox.delivered.is_(False))):
            continue
        db.add(Outbox(topic='report.generate', object_id=report.id))
        audit(db, None, 'report.queue_recovered', report.id)
        recovered += 1
    return recovered


@celery.task
def reference_sync(identifier):
    with Session.begin() as db:
        job = db.scalar(select(ReferenceSync).where(ReferenceSync.id == identifier).with_for_update())
        if job is None or job.state == 'completed':
            return
        try:
            text = fetch(REFERENCE_URL, max_bytes=64 * 1024 * 1024)
            with db.begin_nested():
                count, checksum = synchronize(db, text)
            job.state, job.item_count, job.checksum, job.completed_at = 'completed', count, checksum, now()
            job.error = None
            audit(db, None, 'attack.synchronized', identifier, {'count': count, 'sha256': checksum, 'source': REFERENCE_URL})
        except Exception as exc:
            job.state, job.error, job.completed_at = 'failed', type(exc).__name__, now()
            audit(db, None, 'attack.sync_failed', identifier, {'error_type': type(exc).__name__})


@celery.task
def risk_snapshot(identifier=None):
    with Session.begin() as db:
        capture_risk(db)


@celery.task
def export_generate(identifier):
    return generate_export(identifier)
