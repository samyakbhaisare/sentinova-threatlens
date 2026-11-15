import asyncio
import anyio
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta

import httpx
import pyotp
import redis
import redis.asyncio as aioredis
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter as MetricCounter, Gauge, Histogram, generate_latest
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm.exc import StaleDataError

from . import schemas as s
from .config import settings
from .correlation import correlate
from .db import get_db
from .enrichment import latest
from .feeds import ADAPTERS, validate_url
from .intelligence import ingest
from .models import Alert, AlertRule, Audit, EventObservable, Feed, Hunt, Incident, IncidentLink, Indicator, Notification, Outbox, Provenance, Refresh, Relationship, Report, Reset, SecurityEvent, Sighting, Timeline, User, now, uid
from .reporting import csv_export, report_path, stix_export
from .security import PERMISSIONS, audit, current_user, decrypt, digest, encrypt, hasher, issue, require, require_stateless
from .search import build_query, event_channel
from .realtime import Hello, authenticate as authenticate_ws, record_disconnect
from starlette.concurrency import run_in_threadpool
from .geography import target_points
from .classification import allowed_labels, ensure_monotonic, expect_version, highest, incident_label, incident_labels, raise_linked_incidents
from .attack import REFERENCE_URL, coverage as attack_coverage, replace_mappings
from .models import ReferenceSync, RiskSnapshot, ReportItem
from .bulk_exports import router as bulk_export_router
from .event_identity import equivalent as equivalent_event
from .observability import configure

app = FastAPI(title='Sentinova ThreatLens', version='1.0.0', docs_url='/api/docs', openapi_url='/api/openapi.json')
app.include_router(bulk_export_router)
config = settings()
app.add_middleware(CORSMiddleware, allow_origins=[config.origin], allow_credentials=True, allow_methods=['GET', 'POST', 'PATCH'], allow_headers=['Authorization', 'Content-Type'])
logger = configure('threatlens.api')
requests = MetricCounter('threatlens_requests_total', 'Requests', ['method', 'status'])
latency = Histogram('threatlens_request_seconds', 'API latency')
heartbeat = Gauge('threatlens_service_heartbeat_timestamp_seconds', 'Last service heartbeat', ['service'])
dependency_up = Gauge('threatlens_dependency_up', 'Dependency readiness', ['dependency'])
readiness_up = Gauge('threatlens_readiness_up', 'API readiness (every dependency healthy)')
outbox_pending = Gauge('threatlens_outbox_pending', 'Undelivered outbox rows')
DB = Depends(get_db)


def serial(row, exclude=()):
    return {col.name: getattr(row, col.name) for col in row.__table__.columns if col.name not in exclude}


def public_user(user):
    return serial(user, ('password_hash', 'mfa_secret', 'failures', 'locked_until', 'token_version', 'mfa_step'))


def get(db, model, identifier):
    obj = db.get(model, identifier)
    if obj is None:
        raise HTTPException(404, 'Record not found')
    return obj


def locked_get(db, model, identifier):
    row = db.scalar(select(model).where(model.id == identifier).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise HTTPException(404, 'Record not found')
    return row


def track(db, request, user, action, object_id=None, data=None):
    audit(db, user.id if user else None, action, object_id, data, getattr(request.state, 'correlation_id', None))


@app.middleware('http')
async def boundary(request: Request, call_next):
    request.state.correlation_id = uid()
    start = time.monotonic()
    # Check actual streamed bytes, including chunked requests, before JSON parsing.
    if request.method in ('POST', 'PATCH', 'PUT'):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1024 * 1024:
                return JSONResponse({'error_code': 'request_too_large', 'message': 'Limit is 1 MiB', 'correlation_id': request.state.correlation_id}, status_code=413)
        request._body = bytes(body)
    if not config.test_mode and request.url.path.startswith('/api/v1'):
        try:
            cache = aioredis.from_url(config.redis_url, socket_connect_timeout=2, socket_timeout=2)
            identity = request.client.host if request.client else 'unknown'
            authorization = request.headers.get('authorization', '')
            if authorization.startswith('Bearer '):
                import jwt
                try:
                    claims = jwt.decode(authorization[7:], config.signing_key(), algorithms=['HS256'], issuer='threatlens', audience='threatlens-api')
                    identity = 'user:' + claims['sub']
                except (jwt.PyJWTError, KeyError):
                    pass
            identity = digest(identity)
            key = f'limit:{identity}:{int(time.time() // 60)}'
            async with cache.pipeline(transaction=True) as pipe:
                count, _ = await pipe.incr(key).expire(key, 70).execute()
            await cache.aclose()
            if count > 300:
                return JSONResponse({'error_code': 'rate_limited', 'message': 'Request budget exceeded', 'correlation_id': request.state.correlation_id}, status_code=429)
        except redis.RedisError:
            return JSONResponse({'error_code': 'dependency_unavailable', 'message': 'Rate limiter unavailable', 'correlation_id': request.state.correlation_id}, status_code=503)
    response = await call_next(request)
    response.headers.update({'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'X-Correlation-ID': request.state.correlation_id, 'Cache-Control': 'no-store'})
    if config.production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    requests.labels(request.method, response.status_code).inc()
    latency.observe(time.monotonic() - start)
    logger.info(json.dumps({'method': request.method, 'status': response.status_code, 'correlation_id': request.state.correlation_id, 'duration_ms': round((time.monotonic() - start) * 1000, 2)}))
    return response


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    return JSONResponse({'error_code': f'http_{exc.status_code}', 'message': exc.detail, 'correlation_id': getattr(request.state, 'correlation_id', None)}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return JSONResponse({'error_code': 'validation_error', 'message': 'Invalid request fields', 'fields': ['.'.join(map(str, e['loc'])) for e in exc.errors()], 'correlation_id': request.state.correlation_id}, status_code=422)


@app.exception_handler(IntegrityError)
async def integrity_error(request, exc):
    return JSONResponse({'error_code': 'conflict', 'message': 'Duplicate or invalid reference', 'correlation_id': request.state.correlation_id}, status_code=409)


@app.exception_handler(StaleDataError)
async def stale_write(request, exc):
    return JSONResponse({'error_code': 'stale_version', 'message': 'Concurrent update; refresh and retry', 'correlation_id': request.state.correlation_id}, status_code=409)


@app.exception_handler(OperationalError)
async def database_unavailable(request, exc):
    return JSONResponse({'error_code': 'dependency_unavailable', 'message': 'Database unavailable; retry after service recovery', 'correlation_id': request.state.correlation_id}, status_code=503)


def cookies(response, raw):
    response.set_cookie('refresh_token', raw, httponly=True, secure=config.production, samesite='strict', path='/api/v1/auth', max_age=604800)


def check_origin(request):
    if request.headers.get('origin') and request.headers['origin'] != config.origin:
        raise HTTPException(403, 'Origin denied')


@app.post('/api/v1/auth/login')
def login(body: s.Login, request: Request, response: Response, db: DBSession = DB):
    user = db.scalar(select(User).where(User.email == body.email.lower()).with_for_update())
    valid = False
    if user and user.enabled and (not user.locked_until or user.locked_until <= now()):
        try:
            valid = hasher.verify(user.password_hash, body.password)
        except VerificationError:
            valid = False
        if valid and user.mfa_enabled:
            step = int(time.time() // 30)
            valid = bool(body.totp and pyotp.TOTP(decrypt(user.mfa_secret)).verify(body.totp) and step > user.mfa_step)
            if valid:
                user.mfa_step = step
    if not valid:
        if user:
            user.failures += 1
            user.locked_until = now() + timedelta(seconds=min(900, 2 ** min(user.failures, 10)))
        track(db, request, user, 'auth.login_failed')
        db.commit()
        raise HTTPException(401, 'Invalid credentials or account temporarily locked')
    user.failures, user.locked_until = 0, None
    token, refresh = issue(db, user)
    track(db, request, user, 'auth.login')
    cookies(response, refresh)
    return {'access_token': token, 'token_type': 'bearer', 'expires_in': 600, 'user': public_user(user)}


@app.post('/api/v1/auth/refresh')
def refresh(request: Request, response: Response, db: DBSession = DB):
    check_origin(request)
    raw = request.cookies.get('refresh_token', '')
    row = db.scalar(select(Refresh).where(Refresh.digest == digest(raw)).with_for_update())
    if not row:
        track(db, request, None, 'auth.refresh_failed')
        db.commit()
        raise HTTPException(401, 'Invalid refresh credential')
    user = db.get(User, row.user_id)
    if row.used:
        db.execute(update(Refresh).where(Refresh.family == row.family).values(revoked=True))
        user.token_version += 1
        track(db, request, user, 'auth.refresh_reuse')
        db.commit()
        raise HTTPException(401, 'Refresh reuse detected; session family revoked')
    if row.revoked or row.expires_at <= now() or not user.enabled:
        track(db, request, user, 'auth.refresh_failed')
        db.commit()
        raise HTTPException(401, 'Refresh credential expired or revoked')
    row.used = True
    token, raw = issue(db, user, row.family)
    cookies(response, raw)
    track(db, request, user, 'auth.refresh')
    return {'access_token': token, 'user': public_user(user), 'expires_in': 600}


@app.post('/api/v1/auth/logout')
def logout(request: Request, response: Response, user=Depends(current_user), db: DBSession = DB):
    user.token_version += 1
    db.execute(update(Refresh).where(Refresh.user_id == user.id).values(revoked=True))
    response.delete_cookie('refresh_token', path='/api/v1/auth')
    track(db, request, user, 'auth.logout')
    return {'revoked': True}


@app.get('/api/v1/auth/me')
def me(user=Depends(current_user)):
    return {**public_user(user), 'permissions': [p for p, roles in PERMISSIONS.items() if user.role in roles]}


@app.post('/api/v1/auth/reset')
def reset_password(body: s.PasswordReset, request: Request, db: DBSession = DB):
    row = db.scalar(select(Reset).where(Reset.digest == digest(body.token)).with_for_update())
    if not row or row.used or row.expires_at <= now():
        track(db, request, None, 'auth.reset_failed')
        db.commit()
        raise HTTPException(401, 'Reset credential invalid or expired')
    user = db.get(User, row.user_id)
    user.password_hash = hasher.hash(body.password)
    user.token_version += 1
    user.failures, user.locked_until = 0, None
    row.used = True
    db.execute(update(Refresh).where(Refresh.user_id == user.id).values(revoked=True))
    track(db, request, user, 'auth.password_reset')
    return {'reset': True}


@app.post('/api/v1/auth/mfa/setup')
def mfa_setup(body: s.MFA, request: Request, user=Depends(current_user), db: DBSession = DB):
    if user.role not in ('administrator', 'security_engineer', 'incident_responder') or user.mfa_enabled:
        raise HTTPException(403, 'MFA setup unavailable')
    try:
        hasher.verify(user.password_hash, body.password)
    except VerificationError:
        raise HTTPException(401, 'Password incorrect') from None
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt(secret)
    track(db, request, user, 'auth.mfa_setup')
    return {'provisioning_uri': pyotp.TOTP(secret).provisioning_uri(user.email, issuer_name='Sentinova ThreatLens')}


@app.post('/api/v1/auth/mfa/confirm')
def mfa_confirm(body: s.MFA, request: Request, user=Depends(current_user), db: DBSession = DB):
    if not user.mfa_secret or not body.code or not pyotp.TOTP(decrypt(user.mfa_secret)).verify(body.code):
        raise HTTPException(401, 'Invalid TOTP')
    user.mfa_enabled = True
    user.mfa_step = int(time.time() // 30)
    track(db, request, user, 'auth.mfa_enabled')
    return {'enabled': True}


@app.get('/api/v1/users')
def users(user=Depends(require('user')), db: DBSession = DB, offset: int = Query(0, ge=0)):
    return {'items': [public_user(u) for u in db.scalars(select(User).order_by(User.created_at).offset(offset).limit(100))]}


@app.post('/api/v1/users', status_code=201)
def create_user(body: s.UserCreate, request: Request, user=Depends(require('user')), db: DBSession = DB):
    row = User(email=body.email.lower(), name=body.name, role=body.role, password_hash=hasher.hash(body.password))
    db.add(row)
    db.flush()
    track(db, request, user, 'user.created', row.id, {'role': row.role})
    return public_user(row)


@app.patch('/api/v1/users/{identifier}')
def change_user(identifier: str, body: s.UserPatch, request: Request, user=Depends(require('user')), db: DBSession = DB):
    target = get(db, User, identifier)
    if identifier == user.id:
        raise HTTPException(409, 'Self-demotion and self-disable are not permitted')
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(target, k, v)
    target.token_version += 1
    db.execute(update(Refresh).where(Refresh.user_id == target.id).values(revoked=True))
    track(db, request, user, 'user.updated', identifier, body.model_dump(exclude_none=True))
    return public_user(target)


@app.post('/api/v1/users/{identifier}/reset-token')
def reset_token(identifier: str, request: Request, user=Depends(require('user')), db: DBSession = DB):
    get(db, User, identifier)
    raw = secrets.token_urlsafe(48)
    db.add(Reset(user_id=identifier, digest=digest(raw), expires_at=now() + timedelta(minutes=15)))
    track(db, request, user, 'auth.reset_issued', identifier)
    return {'token': raw, 'expires_in': 900, 'delivery': 'Administrator must deliver over a verified private channel'}


@app.get('/api/v1/feeds')
def feeds(user=Depends(require('feed')), db: DBSession = DB):
    return {'items': [serial(f) for f in db.scalars(select(Feed).order_by(Feed.name))]}


@app.post('/api/v1/feeds', status_code=201)
def create_feed(body: s.FeedCreate, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    try:
        validate_url(body.url)
        if body.adapter not in ADAPTERS:
            raise ValueError('Unknown adapter')
    except (ValueError, OSError) as exc:
        raise HTTPException(422, str(exc)) from None
    row = Feed(**body.model_dump())
    db.add(row)
    db.flush()
    track(db, request, user, 'feed.created', row.id)
    return serial(row)


@app.patch('/api/v1/feeds/{identifier}')
def update_feed(identifier: str, body: s.FeedPatch, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    row = get(db, Feed, identifier)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(row, k, v)
    track(db, request, user, 'feed.updated', identifier, body.model_dump(exclude_none=True))
    return serial(row)


@app.post('/api/v1/feeds/{identifier}/poll', status_code=202)
def repoll(identifier: str, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    if not get(db, Feed, identifier).enabled:
        raise HTTPException(409, 'Feed disabled')
    db.add(Outbox(topic='feed.poll', object_id=identifier))
    track(db, request, user, 'feed.poll_requested', identifier)
    return {'state': 'queued'}


@app.get('/api/v1/feeds/{identifier}/diagnostics')
def feed_diagnostics(identifier: str, user=Depends(require('feed')), db: DBSession = DB):
    get(db, Feed, identifier)
    query = select(Audit).where(Audit.object_id == identifier, Audit.action.like('feed.%')).order_by(Audit.created_at.desc(), Audit.id).limit(100)
    return {'items': [serial(row) for row in db.scalars(query)]}


@app.get('/api/v1/indicators')
def indicators(q: str = Query('', max_length=200), type: str | None = None, status: str | None = None, min_score: int = Query(0, ge=0, le=100), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), user=Depends(require('search')), db: DBSession = DB):
    query = select(Indicator).where(Indicator.score >= min_score)
    if q:
        query = query.where(Indicator.value.ilike('%' + q.replace('%', '\\%').replace('_', '\\_') + '%', escape='\\'))
    if type:
        query = query.where(Indicator.type == type)
    if status:
        query = query.where(Indicator.status == status)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    return {'items': [serial(i) for i in db.scalars(query.order_by(Indicator.score.desc(), Indicator.id).offset(offset).limit(limit))], 'total': total, 'offset': offset}


@app.post('/api/v1/indicators', status_code=201)
def create_indicator(body: s.IndicatorCreate, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    feed = db.scalar(select(Feed).where(Feed.name == 'Analyst submissions'))
    if not feed:
        feed = Feed(name='Analyst submissions', adapter='json', url='internal', enabled=False, reliability=0)
        db.add(feed)
        db.flush()
    row = ingest(db, feed, body.model_dump())
    correlate(db, indicator=row)
    track(db, request, user, 'indicator.created', row.id)
    return serial(row)


@app.get('/api/v1/indicators/{identifier}')
def indicator(identifier: str, user=Depends(require('search')), db: DBSession = DB):
    row = get(db, Indicator, identifier)
    sources = [dict(serial(p), feed_name=f.name) for p, f in db.execute(select(Provenance, Feed).join(Feed).where(Provenance.indicator_id == identifier))]
    sightings = [serial(e) for e in db.scalars(select(SecurityEvent).join(Sighting).where(Sighting.indicator_id == identifier).limit(100))]
    edges = [serial(e) for e in db.scalars(select(Relationship).where(or_(Relationship.source_id == identifier, Relationship.target_id == identifier)))]
    links = list(db.scalars(select(IncidentLink.incident_id).where(IncidentLink.indicator_id == identifier)))
    return {**serial(row), 'sources': sources, 'enrichments': latest(db, identifier), 'sightings': sightings, 'relationships': edges,
            'incident_ids': links}


@app.get('/api/v1/indicators/{identifier}/history')
def indicator_history(identifier: str, offset: int = Query(0, ge=0), user=Depends(require('search')), db: DBSession = DB):
    get(db, Indicator, identifier)
    query = select(Audit).where(Audit.object_id == identifier, Audit.action.like('indicator.%')).order_by(Audit.created_at.desc(), Audit.id).offset(offset).limit(100)
    return {'items': [serial(item) for item in db.scalars(query)]}


def ioc_edit_scope(db, user, identifier, canonical_change=False):
    if user.role == 'incident_responder' and not db.scalar(select(IncidentLink.id).where(IncidentLink.indicator_id == identifier).limit(1)):
        raise HTTPException(403, 'Responder edits require an incident link')
    if canonical_change and user.role not in ('administrator', 'security_engineer', 'incident_responder'):
        raise HTTPException(403, 'Canonical lifecycle changes require engineer or contextual responder privileges')


@app.patch('/api/v1/indicators/{identifier}')
def edit_indicator(identifier: str, body: s.IndicatorPatch, request: Request, user=Depends(require('tag')), db: DBSession = DB):
    row = locked_get(db, Indicator, identifier)
    expect_version(row, body.expected_version)
    changes = body.model_dump(exclude_none=True, exclude={'expected_version', 'annotation_tlp'})
    ioc_edit_scope(db, user, identifier, bool(set(changes) & {'status', 'tlp', 'ttl_days'}))
    ensure_monotonic(row.tlp, body.tlp)
    if row.notes:
        ensure_monotonic(row.notes_tlp, body.notes_tlp)
    before = {k: getattr(row, k) for k in changes if k != 'ttl_days'}
    before['tlp'] = row.tlp
    if 'ttl_days' in changes:
        before['expires_at'] = row.expires_at.isoformat()
    if changes.get('status') == 'active' and 'ttl_days' not in changes:
        from datetime import timezone
        expiry = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
        if expiry <= now():
            raise HTTPException(422, 'Reactivating an expired IOC requires a new TTL')
    for k, v in changes.items():
        if k == 'ttl_days':
            row.expires_at = now() + timedelta(days=v)
        else:
            setattr(row, k, v)
    if row.notes:
        row.tlp = highest(row.tlp, row.notes_tlp)
    if body.tags is not None or body.techniques is not None:
        row.tlp = highest(row.tlp, body.annotation_tlp or 'amber')
    if body.techniques is not None:
        replace_mappings(db, identifier, body.techniques)
    raise_linked_incidents(db, row)
    db.add(Outbox(topic='indicators', object_id=identifier))
    track(db, request, user, 'indicator.updated', identifier, {'before': before, 'after': changes, 'effective_tlp': row.tlp})
    for link in db.scalars(select(IncidentLink).where(IncidentLink.indicator_id == identifier)):
        db.add(Timeline(incident_id=link.incident_id, actor_id=user.id, kind='indicator_updated', tlp=row.tlp, data={'indicator_id': identifier, 'changes': changes}))
        db.add(Outbox(topic='incidents.' + link.incident_id, object_id=link.incident_id))
    db.flush()
    return serial(row)


@app.post('/api/v1/indicators/{identifier}/relationships', status_code=201)
def relationship(identifier: str, body: s.Edge, request: Request, user=Depends(require('tag')), db: DBSession = DB):
    source, target = get(db, Indicator, identifier), get(db, Indicator, body.target_id)
    ioc_edit_scope(db, user, identifier)
    if source.id == target.id:
        raise HTTPException(422, 'An IOC cannot relate to itself')
    if body.kind == 'resolves-to' and (source.type != 'domain' or target.type != 'ip'):
        raise HTTPException(422, 'resolves-to requires domain → IP')
    row = Relationship(source_id=identifier, **body.model_dump())
    db.add(row)
    track(db, request, user, 'indicator.relationship_added', identifier, body.model_dump())
    return {'created': True}


@app.post('/api/v1/indicators/{identifier}/enrich', status_code=202)
def request_enrichment(identifier: str, request: Request, user=Depends(require('enrich')), db: DBSession = DB):
    get(db, Indicator, identifier)
    db.add(Outbox(topic='indicator.enrich', object_id=identifier))
    track(db, request, user, 'indicator.enrichment_requested', identifier)
    return {'state': 'queued', 'indicator_id': identifier}


def analysis(db, kind, value):
    from .intelligence import canonical
    try:
        value = canonical(kind, value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    row = db.scalar(select(Indicator).where(Indicator.type == kind, Indicator.value == value))
    if not row:
        raise HTTPException(404, 'Indicator not stored; create it before requesting enrichment')
    return {'indicator_id': row.id, 'results': latest(db, row.id), 'score': row.score, 'breakdown': row.breakdown}


@app.get('/api/v1/reputation/ip/{value}')
def ip_analysis(value: str, user=Depends(require('search')), db: DBSession = DB):
    return analysis(db, 'ip', value)


@app.get('/api/v1/domains/{value}/analysis')
def domain_analysis(value: str, user=Depends(require('search')), db: DBSession = DB):
    return analysis(db, 'domain', value)


@app.get('/api/v1/hash/{value}')
def hash_analysis(value: str, user=Depends(require('search')), db: DBSession = DB):
    return analysis(db, {32: 'hash_md5', 40: 'hash_sha1', 64: 'hash_sha256'}.get(len(value), 'invalid'), value)


@app.post('/api/v1/events', status_code=201)
def create_event(body: s.EventCreate, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    values = body.model_dump(mode='json')
    fingerprint = digest(json.dumps(values, sort_keys=True, separators=(',', ':')))
    old = db.scalar(select(SecurityEvent).where(SecurityEvent.source == body.source, SecurityEvent.external_id == body.external_id))
    if old:
        if old.digest != fingerprint and not equivalent_event(old, body):
            raise HTTPException(409, 'Idempotency key reused with different event data')
        return {'id': old.id, 'replayed': True}
    values['occurred_at'] = body.occurred_at
    event = SecurityEvent(**values, digest=fingerprint)
    db.add(event)
    db.flush()
    for kind, value in {(o.type, o.value) for o in body.observables}:
        db.add(EventObservable(event_id=event.id, type=kind, value=value))
    db.flush()
    correlate(db, event=event)
    db.add(Outbox(topic='events', object_id=event.id))
    track(db, request, user, 'event.ingested', event.id, {'source': body.source, 'controlled_test': body.controlled_test})
    return {'id': event.id, 'replayed': False}


@app.post('/api/v1/integrations/{kind}/events', status_code=201)
def integration_event(kind: str, body: s.EventCreate, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    if kind not in ('siem', 'edr', 'ticketing'):
        raise HTTPException(404, 'Unknown integration type')
    body.source = kind + ':' + body.source[:90]
    return create_event(body, request, user, db)


@app.get('/api/v1/alert-rules')
def rules(user=Depends(require('search')), db: DBSession = DB):
    return {'items': [serial(r) for r in db.scalars(select(AlertRule))]}


@app.post('/api/v1/alert-rules', status_code=201)
def rule_create(body: s.RuleCreate, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    if body.feed_id:
        get(db, Feed, body.feed_id)
    if body.recipient_id:
        recipient = get(db, User, body.recipient_id)
        if recipient.role == 'executive' or not recipient.enabled:
            raise HTTPException(422, 'Recipient must be an enabled operational user')
    row = AlertRule(**body.model_dump())
    db.add(row)
    db.flush()
    track(db, request, user, 'rule.created', row.id)
    return serial(row)


@app.patch('/api/v1/alert-rules/{identifier}')
def rule_update(identifier: str, body: s.RulePatch, request: Request, user=Depends(require('feed')), db: DBSession = DB):
    row = locked_get(db, AlertRule, identifier)
    expect_version(row, body.expected_version)
    changes = body.model_dump(exclude_unset=True, exclude={'expected_version'})
    if body.feed_id:
        get(db, Feed, body.feed_id)
    if body.recipient_id:
        recipient = get(db, User, body.recipient_id)
        if not recipient.enabled or recipient.role == 'executive':
            raise HTTPException(422, 'Recipient must be an enabled operational user')
    before = {key: getattr(row, key) for key in changes}
    for key, value in changes.items():
        setattr(row, key, value)
    track(db, request, user, 'rule.updated', identifier, {'before': before, 'after': changes})
    db.flush()
    return serial(row)


@app.get('/api/v1/assignees')
def assignees(user=Depends(require('search')), db: DBSession = DB):
    query = select(User).where(User.enabled.is_(True), User.role != 'executive').order_by(User.name).limit(500)
    return {'items': [{'id': row.id, 'name': row.name, 'role': row.role} for row in db.scalars(query)]}


@app.get('/api/v1/alerts')
def alerts(state: str | None = None, days: int | None = Query(None, ge=1, le=365), offset: int = Query(0, ge=0), user=Depends(require('search')), db: DBSession = DB):
    query = select(Alert, Indicator.value, User.name).join(Indicator).outerjoin(User, User.id == Alert.assignee_id)
    if user.role not in ('administrator', 'incident_responder'):
        query = query.where(or_(Alert.recipient_id.is_(None), Alert.recipient_id == user.id))
    if state:
        query = query.where(Alert.state == state)
    if days:
        query = query.where(Alert.created_at >= now() - timedelta(days=days))
    return {'items': [{**serial(a), 'value': v, 'assignee_name': name} for a, v, name in db.execute(query.order_by(Alert.score.desc(), Alert.created_at, Alert.id).offset(offset).limit(100))]}


@app.patch('/api/v1/alerts/{identifier}')
def alert_change(identifier: str, body: s.AlertPatch, request: Request, user=Depends(require('alert')), db: DBSession = DB):
    row = db.scalar(select(Alert).where(Alert.id == identifier).with_for_update())
    if not row:
        raise HTTPException(404, 'Alert not found')
    expect_version(row, body.expected_version)
    if row.recipient_id and row.recipient_id != user.id and user.role not in ('administrator', 'incident_responder'):
        raise HTTPException(403, 'Alert routed to another user')
    if user.role in ('security_engineer', 'threat_hunter'):
        if row.assignee_id not in (None, user.id) or body.state not in (None, 'acknowledged', 'in-progress') or body.assignee_id not in (None, user.id):
            raise HTTPException(403, 'Limited role can triage only alerts assigned to or claimable by self')
    states = ['new', 'acknowledged', 'in-progress', 'resolved', 'closed']
    if body.state and body.state != row.state and states.index(body.state) != states.index(row.state) + 1:
        raise HTTPException(409, 'Invalid alert lifecycle transition')
    previous = {'state': row.state, 'assignee_id': row.assignee_id}
    if body.assignee_id:
        target = get(db, User, body.assignee_id)
        if target.role == 'executive' or not target.enabled:
            raise HTTPException(422, 'Invalid operational assignee')
        row.assignee_id = body.assignee_id
    elif 'assignee_id' in body.model_fields_set:
        row.assignee_id = None
    if body.state:
        row.state = body.state
    row.updated_at = now()
    track(db, request, user, 'alert.updated', identifier, {'before': previous, 'after': body.model_dump(exclude_unset=True)})
    db.add(Outbox(topic='alerts.stream', object_id=identifier))
    for link in db.scalars(select(IncidentLink).where(IncidentLink.alert_id == identifier)):
        db.add(Timeline(incident_id=link.incident_id, actor_id=user.id, kind='alert_updated', data={'alert_id': identifier, 'state': row.state}))
        db.add(Outbox(topic='incidents.' + link.incident_id, object_id=link.incident_id))
    db.flush()
    return serial(row)


@app.get('/api/v1/alerts/{identifier}/history')
def alert_history(identifier: str, user=Depends(require('search')), db: DBSession = DB):
    row = get(db, Alert, identifier)
    if row.recipient_id and row.recipient_id != user.id and user.role not in ('administrator', 'incident_responder'):
        raise HTTPException(403, 'Alert routed to another user')
    return {'items': [serial(item) for item in db.scalars(select(Audit).where(Audit.object_id == identifier, Audit.action.like('alert.%')).order_by(Audit.created_at, Audit.id))]}


def incident_scope(user, row, write=False):
    if user.role in ('administrator', 'incident_responder'):
        return
    if user.role not in ('soc_analyst', 'threat_hunter') or (write and row.creator_id != user.id and row.owner_id != user.id):
        raise HTTPException(403, 'Incident context denied')


@app.get('/api/v1/incidents')
def incidents(days: int | None = Query(None, ge=1, le=365), user=Depends(require('incident')), db: DBSession = DB):
    query = select(Incident)
    if days:
        query = query.where(Incident.created_at >= now() - timedelta(days=days))
    rows = list(db.scalars(query.order_by(Incident.created_at.desc()).limit(100)))
    labels = incident_labels(db, rows)
    return {'items': [{**serial(i), 'tlp': labels[i.id]} for i in rows]}


@app.post('/api/v1/incidents', status_code=201)
def create_incident(body: s.IncidentCreate, request: Request, user=Depends(require('incident')), db: DBSession = DB):
    ioc = get(db, Indicator, body.indicator_id)
    if body.alert_id:
        alert = get(db, Alert, body.alert_id)
        if alert.indicator_id != body.indicator_id:
            raise HTTPException(422, 'Alert does not refer to selected indicator')
        if alert.recipient_id and alert.recipient_id != user.id and user.role not in ('administrator', 'incident_responder'):
            raise HTTPException(403, 'Alert routing context denied')
    row = Incident(title=body.title, owner_id=user.id, creator_id=user.id, tlp=highest(body.tlp, ioc.tlp))
    db.add(row)
    db.flush()
    db.add(IncidentLink(incident_id=row.id, indicator_id=body.indicator_id, alert_id=body.alert_id))
    db.add(Timeline(incident_id=row.id, actor_id=user.id, kind='opened', tlp=row.tlp, data=body.model_dump()))
    for sighting in db.scalars(select(Sighting).where(Sighting.indicator_id == body.indicator_id)):
        db.add(Timeline(incident_id=row.id, actor_id=user.id, kind='linked_event', data={'event_id': sighting.event_id, 'indicator_id': body.indicator_id}))
    db.add(Outbox(topic='incidents.' + row.id, object_id=row.id))
    track(db, request, user, 'incident.created', row.id)
    return serial(row)


@app.get('/api/v1/incidents/{identifier}/timeline')
def timeline(identifier: str, user=Depends(require('incident')), db: DBSession = DB):
    row = get(db, Incident, identifier)
    incident_scope(user, row)
    return {'incident': {**serial(row), 'tlp': incident_label(db, row)}, 'items': [serial(t) for t in db.scalars(select(Timeline).where(Timeline.incident_id == identifier).order_by(Timeline.created_at, Timeline.id))],
            'links': [serial(l) for l in db.scalars(select(IncidentLink).where(IncidentLink.incident_id == identifier))]}


@app.post('/api/v1/incidents/{identifier}/timeline', status_code=201)
def append_timeline(identifier: str, body: s.Note, request: Request, user=Depends(require('incident')), db: DBSession = DB):
    incident = locked_get(db, Incident, identifier)
    incident_scope(user, incident, True)
    incident.tlp = highest(incident.tlp, body.tlp)
    db.add(Timeline(incident_id=identifier, actor_id=user.id, kind='analyst_note', tlp=highest(incident.tlp, body.tlp), data=body.model_dump()))
    db.add(Outbox(topic='incidents.' + identifier, object_id=identifier))
    track(db, request, user, 'incident.note_added', identifier)
    return {'appended': True}


@app.patch('/api/v1/incidents/{identifier}')
def change_incident(identifier: str, body: s.IncidentPatch, request: Request, user=Depends(require('incident')), db: DBSession = DB):
    row = locked_get(db, Incident, identifier)
    expect_version(row, body.expected_version)
    ensure_monotonic(row.tlp, body.tlp)
    if user.role not in ('administrator', 'incident_responder'):
        raise HTTPException(403, 'Incident management requires responder privileges')
    states = ['open', 'resolved', 'closed']
    if body.state and body.state != row.state and states.index(body.state) != states.index(row.state) + 1:
        raise HTTPException(409, 'Invalid incident lifecycle transition')
    if body.owner_id:
        target = get(db, User, body.owner_id)
        if target.role not in ('administrator', 'incident_responder') or not target.enabled:
            raise HTTPException(422, 'Owner must be an enabled responder')
    for k, v in body.model_dump(exclude_none=True, exclude={'expected_version'}).items():
        setattr(row, k, v)
    db.add(Timeline(incident_id=identifier, actor_id=user.id, kind='updated', tlp=row.tlp, data=body.model_dump(exclude_none=True)))
    db.add(Outbox(topic='incidents.' + identifier, object_id=identifier))
    track(db, request, user, 'incident.updated', identifier, body.model_dump(exclude_none=True))
    db.flush()
    return serial(row)


@app.post('/api/v1/incidents/{identifier}/links', status_code=201)
def link_incident(identifier: str, body: s.IncidentLinkCreate, request: Request, user=Depends(require('incident')), db: DBSession = DB):
    row = locked_get(db, Incident, identifier)
    incident_scope(user, row, True)
    if row.state != 'open':
        raise HTTPException(409, 'New evidence links require an open incident')
    ioc = get(db, Indicator, body.indicator_id)
    if body.alert_id:
        alert = get(db, Alert, body.alert_id)
        if alert.indicator_id != body.indicator_id:
            raise HTTPException(422, 'Alert and IOC must match')
        if alert.recipient_id and alert.recipient_id != user.id and user.role not in ('administrator', 'incident_responder'):
            raise HTTPException(403, 'Alert routing context denied')
    existing = db.scalar(select(IncidentLink).where(IncidentLink.incident_id == identifier, IncidentLink.indicator_id == body.indicator_id))
    if existing:
        if body.alert_id and existing.alert_id != body.alert_id:
            if existing.alert_id is not None:
                raise HTTPException(409, 'The indicator link already references a different alert')
            existing.alert_id = body.alert_id
            row.tlp = highest(row.tlp, ioc.tlp)
            db.add(Timeline(incident_id=identifier, actor_id=user.id, kind='alert_linked', tlp=row.tlp, data=body.model_dump()))
            db.add(Outbox(topic='incidents.' + identifier, object_id=identifier))
            track(db, request, user, 'incident.alert_linked', identifier, body.model_dump())
            return {'id': existing.id, 'replayed': False}
        return {'id': existing.id, 'replayed': True}
    link = IncidentLink(incident_id=identifier, **body.model_dump())
    row.tlp = highest(row.tlp, ioc.tlp)
    db.add(link)
    db.flush()
    db.add(Timeline(incident_id=identifier, actor_id=user.id, kind='evidence_linked', tlp=row.tlp, data=body.model_dump()))
    for sighting in db.scalars(select(Sighting).where(Sighting.indicator_id == body.indicator_id)):
        db.add(Timeline(incident_id=identifier, actor_id=user.id, kind='linked_event', data={'indicator_id': body.indicator_id, 'event_id': sighting.event_id}))
    db.add(Outbox(topic='incidents.' + identifier, object_id=identifier))
    track(db, request, user, 'incident.evidence_linked', identifier, body.model_dump())
    return {'id': link.id, 'replayed': False}


@app.get('/api/v1/search')
async def search(q: str = Query('', max_length=500), type: str | None = None, source: str | None = None, tag: str | None = None, technique: str | None = None, kind: str | None = None, min_score: int = Query(0, ge=0, le=100), offset: int = Query(0, ge=0, le=9800), user=Depends(require_stateless('search'))):
    query = build_query(q, type, source, tag, technique, kind, min_score)
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            result = await client.post(config.search_url + '/' + config.search_index + '/_search', json={'query': query, 'from': offset, 'size': 50, 'track_total_hits': True, 'aggs': {f: {'terms': {'field': f + '.keyword'}} for f in ('type', 'category', 'sources', 'source')}})
        if result.status_code == 404:
            return {'items': [], 'total': 0, 'facets': {}, 'index_state': 'not_yet_created'}
        result.raise_for_status()
        payload = result.json()
        return {'items': [h['_source'] for h in payload['hits']['hits']], 'total': payload['hits']['total']['value'], 'facets': payload.get('aggregations', {})}
    except httpx.HTTPError:
        raise HTTPException(503, 'Search service unavailable; retry later') from None


@app.get('/api/v1/hunts')
def hunts(user=Depends(require('hunt')), db: DBSession = DB):
    return {'items': [serial(h) for h in db.scalars(select(Hunt).where(Hunt.owner_id == user.id))]}


@app.post('/api/v1/hunts', status_code=201)
def save_hunt(body: s.HuntCreate, request: Request, user=Depends(require('hunt')), db: DBSession = DB):
    row = Hunt(owner_id=user.id, **body.model_dump())
    db.add(row)
    db.flush()
    track(db, request, user, 'hunt.saved', row.id)
    return serial(row)


@app.patch('/api/v1/layout')
def layout(body: s.Layout, request: Request, user=Depends(current_user), db: DBSession = DB):
    user.layout = list(dict.fromkeys(body.widgets))
    track(db, request, user, 'layout.saved', user.id)
    return {'widgets': user.layout}


@app.get('/api/v1/dashboard')
def dashboard(days: int = Query(30, ge=1, le=365), user=Depends(require('dashboard')), db: DBSession = DB):
    since = now() - timedelta(days=days)
    active = Indicator.status == 'active'
    total, mean = db.execute(select(func.count(), func.avg(Indicator.score)).where(active)).one()
    high = db.scalar(select(func.count()).select_from(Indicator).where(active, Indicator.score >= 70))
    categories = [{'name': name, 'count': count} for name, count in db.execute(select(Indicator.category, func.count()).where(active).group_by(Indicator.category).order_by(func.count().desc()).limit(10))]
    trends = [{'date': str(day), 'count': count, 'risk': round(float(risk), 1)} for day, count, risk in db.execute(select(func.date(Indicator.created_at), func.count(), func.avg(Indicator.score)).where(Indicator.created_at >= since).group_by(func.date(Indicator.created_at)).order_by(func.date(Indicator.created_at)))]
    severity = [{'name': name, 'count': db.scalar(select(func.count()).select_from(Indicator).where(active, Indicator.score >= low, Indicator.score < high_limit))} for name, low, high_limit in [('critical', 90, 101), ('high', 70, 90), ('medium', 40, 70), ('low', 0, 40)]]
    sources = [{'name': name, 'count': count} for name, count in db.execute(select(Feed.name, func.count(Provenance.id)).join(Provenance).group_by(Feed.name).order_by(func.count(Provenance.id).desc()).limit(10))]
    alert_states = dict(db.execute(select(Alert.state, func.count()).group_by(Alert.state)).all())
    incident_states = dict(db.execute(select(Incident.state, func.count()).group_by(Incident.state)).all())
    from .models import Enrichment
    points, seen = [], set()
    for row in db.scalars(select(Enrichment).join(Indicator, Indicator.id == Enrichment.indicator_id).where(Indicator.status == 'active', Enrichment.provider == 'ipwhois', Enrichment.expires_at > now()).order_by(Enrichment.created_at.desc()).limit(5000)):
        if row.indicator_id not in seen and row.data.get('latitude') is not None:
            seen.add(row.indicator_id)
            points.append({**row.data, 'indicator_id': row.indicator_id, 'direction': 'origin'})
    correlated_events = db.scalars(select(SecurityEvent).where(SecurityEvent.occurred_at >= since, SecurityEvent.id.in_(select(Sighting.event_id))).limit(5000)).all()
    points.extend(target_points(correlated_events))
    if user.role == 'executive':
        points = [{key: value for key, value in point.items() if key not in ('indicator_id', 'event_id')} for point in points]
    assets = [{'name': a, 'count': c} for a, c in db.execute(select(SecurityEvent.asset, func.count(Sighting.id)).join(Sighting).where(SecurityEvent.occurred_at >= since).group_by(SecurityEvent.asset).order_by(func.count(Sighting.id).desc()).limit(10))]
    return {'active_indicators': total, 'high_critical': high, 'risk_score': round(float(mean), 1) if mean is not None else None,
            'risk_label': 'Mean active IOC priority', 'trends': trends, 'trend_label': 'Intake volume and mean intake priority by day (not historical posture)',
            'categories': categories, 'severity': severity, 'sources': sources, 'alerts': alert_states, 'incidents': incident_states,
            'geo': points, 'assets': assets, 'layout': user.layout, 'generated_at': now()}


@app.get('/api/v1/dashboard/risk-history')
def risk_history(days: int = Query(30, ge=1, le=365), user=Depends(require('dashboard')), db: DBSession = DB):
    rows = db.scalars(select(RiskSnapshot).where(RiskSnapshot.captured_at >= now() - timedelta(days=days)).order_by(RiskSnapshot.bucket_start).limit(9000)).all()
    return {'items': [{'id': row.id, 'bucket_start': row.bucket_start, 'captured_at': row.captured_at, **row.data} for row in rows],
            'metric': 'Measured mean active IOC priority; history starts at actual capture', 'resolution': 'hourly', 'backfilled': False}


@app.post('/api/v1/dashboard/risk-snapshots', status_code=202)
def request_risk_snapshot(request: Request, user=Depends(require('feed')), db: DBSession = DB):
    identifier = uid()
    db.add(Outbox(topic='risk.capture', object_id=identifier))
    track(db, request, user, 'risk.snapshot_requested', identifier)
    return {'state': 'queued'}


@app.get('/api/v1/attack/coverage')
def attack_coverage_view(user=Depends(require('search')), db: DBSession = DB):
    latest_sync = db.scalar(select(ReferenceSync).order_by(ReferenceSync.created_at.desc()).limit(1))
    return {**attack_coverage(db), 'sync': serial(latest_sync) if latest_sync else None}


@app.post('/api/v1/attack/sync', status_code=202)
def request_attack_sync(request: Request, user=Depends(require('feed')), db: DBSession = DB):
    job = ReferenceSync(source_url=REFERENCE_URL)
    db.add(job); db.flush()
    db.add(Outbox(topic='attack.sync', object_id=job.id))
    track(db, request, user, 'attack.sync_requested', job.id)
    return serial(job)


@app.get('/api/v1/notifications')
def notifications(user=Depends(current_user), db: DBSession = DB):
    return {'items': [serial(n) for n in db.scalars(select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(100))]}


@app.patch('/api/v1/notifications/{identifier}/read')
def read_notification(identifier: str, request: Request, user=Depends(current_user), db: DBSession = DB):
    row = get(db, Notification, identifier)
    if row.user_id != user.id:
        raise HTTPException(403, 'Notification belongs to another user')
    row.read = True
    track(db, request, user, 'notification.read', identifier)
    return {'read': True}


@app.get('/api/v1/reports')
def reports(user=Depends(require('report')), db: DBSession = DB):
    query = select(Report)
    if user.role != 'administrator':
        query = query.where(Report.owner_id == user.id)
    if user.role == 'executive':
        query = query.where(Report.tlp != 'red')
    return {'items': [serial(r) for r in db.scalars(query.order_by(Report.created_at.desc()).limit(100))]}


@app.post('/api/v1/reports', status_code=202)
def create_report(body: s.ReportCreate, request: Request, user=Depends(require('report')), db: DBSession = DB):
    if body.incident_id:
        incident_scope(user, get(db, Incident, body.incident_id), True)
    row = Report(owner_id=user.id, **body.model_dump(), next_run=now() + timedelta(hours=body.schedule_hours) if body.schedule_hours else None)
    db.add(row)
    db.flush()
    db.add(Outbox(topic='report.generate', object_id=row.id))
    track(db, request, user, 'report.requested', row.id)
    return serial(row)


@app.get('/api/v1/reports/{identifier}/download')
def download_report(identifier: str, request: Request, user=Depends(require('report')), db: DBSession = DB):
    row = locked_get(db, Report, identifier)
    if row.owner_id != user.id and user.role != 'administrator':
        raise HTTPException(403, 'Report belongs to another user')
    if row.tlp not in ('clear', 'green', 'amber'):
        raise HTTPException(403, 'Restricted or unknown report handling prohibits export')
    source_rows = db.execute(select(Indicator.tlp, ReportItem.tlp).join(ReportItem, ReportItem.indicator_id == Indicator.id).where(ReportItem.report_id == identifier).with_for_update(read=True, of=Indicator)).all()
    if any(current != stored or current not in ('clear', 'green', 'amber') for current, stored in source_rows):
        raise HTTPException(403, 'Report source classification changed; generate a new report')
    if row.incident_id:
        incident = db.scalar(select(Incident).where(Incident.id == row.incident_id).with_for_update(read=True))
        incident_scope(user, incident, True)
        if incident_label(db, incident) == 'red':
            raise HTTPException(403, 'TLP:red incident narrative cannot be exported')
        if db.scalar(select(Indicator.id).join(IncidentLink).where(IncidentLink.incident_id == row.incident_id, Indicator.tlp == 'red').limit(1)):
            raise HTTPException(403, 'TLP:red incident reports cannot be exported')
    if user.role == 'executive':
        evidence = db.scalar(select(Audit).where(Audit.object_id == identifier, Audit.action == 'report.generated').order_by(Audit.created_at.desc()).limit(1))
        if not evidence or evidence.data.get('data', {}).get('audience') != 'executive':
            raise HTTPException(403, 'Generate a new executive summary; prior technical reports are not authorized')
    path = report_path(identifier)
    if row.state != 'ready' or not path.exists():
        raise HTTPException(409, 'Report is not ready')
    if row.checksum:
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != row.checksum:
            raise HTTPException(409, 'Report artifact integrity check failed; regenerate the report')
    proof = db.scalar(select(Audit).where(Audit.object_id == identifier, Audit.action == 'report.generated').order_by(Audit.created_at.desc()).limit(1))
    metadata = proof.data.get('data', {}) if proof else {}
    if metadata.get('manifest_version') != 1 or metadata.get('manifest_count') != len(source_rows):
        raise HTTPException(403, 'Report source manifest is unavailable; regenerate the report')
    track(db, request, user, 'report.downloaded', identifier, {'sha256': row.checksum} if row.checksum else None)
    return FileResponse(path, media_type='application/pdf', filename=f'threatlens-{identifier}.pdf')


@app.post('/api/v1/reports/{identifier}/retry', status_code=202)
def retry_report(identifier: str, request: Request, user=Depends(require('report')), db: DBSession = DB):
    row = locked_get(db, Report, identifier)
    if row.owner_id != user.id and user.role != 'administrator':
        raise HTTPException(403, 'Report belongs to another user')
    if row.state != 'failed' or row.attempts >= 3:
        raise HTTPException(409, 'Report cannot be retried')
    row.state, row.error, row.lease_until = 'queued', None, None
    db.add(Outbox(topic='report.generate', object_id=identifier))
    track(db, request, user, 'report.retry_requested', identifier, {'attempts': row.attempts})
    return serial(row)


@app.patch('/api/v1/reports/{identifier}')
def report_update(identifier: str, body: s.ReportPatch, request: Request, user=Depends(require('report')), db: DBSession = DB):
    row = db.scalar(select(Report).where(Report.id == identifier).with_for_update())
    if row is None:
        raise HTTPException(404, 'Report not found')
    expect_version(row, body.expected_version)
    if row.owner_id != user.id and user.role != 'administrator':
        raise HTTPException(403, 'Report belongs to another user')
    if body.cancel:
        if row.state == 'ready':
            raise HTTPException(409, 'Completed report is retained; disable its schedule instead')
        row.state, row.schedule_hours, row.next_run = 'cancelled', None, None
    elif 'schedule_hours' in body.model_fields_set:
        if row.incident_id:
            incident_scope(user, get(db, Incident, row.incident_id))
        row.schedule_hours = body.schedule_hours
        row.next_run = now() + timedelta(hours=body.schedule_hours) if body.schedule_hours else None
    track(db, request, user, 'report.updated', identifier, body.model_dump(exclude_unset=True))
    db.flush()
    return serial(row)


@app.get('/api/v1/export/{format}')
def export(format: str, request: Request, audience: str = 'public', ids: str | None = Query(None, max_length=4000), user=Depends(require('export')), db: DBSession = DB):
    if format not in ('csv', 'stix') or audience not in ('public', 'internal'):
        raise HTTPException(422, 'Invalid export format or audience')
    allowed = allowed_labels(user.role, audience)
    query = select(Indicator).where(Indicator.tlp.in_(allowed)).order_by(Indicator.score.desc()).limit(1000)
    if ids is not None:
        query = query.where(Indicator.id.in_([value for value in ids.split(',') if value]))
    rows = db.scalars(query.with_for_update(read=True)).all()
    track(db, request, user, 'intelligence.exported', data={'format': format, 'count': len(rows), 'audience': audience, 'tlp_allowed': allowed})
    if format == 'csv':
        return Response(csv_export(rows), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=threatlens.csv'})
    return stix_export(rows)


@app.get('/api/v1/audit')
def audit_log(action: str | None = Query(None, max_length=120), days: int | None = Query(None, ge=1, le=365), offset: int = Query(0, ge=0), user=Depends(require('audit')), db: DBSession = DB):
    query = select(Audit)
    if user.role == 'security_engineer':
        query = query.where(or_(Audit.actor_id == user.id, Audit.action.like('feed.%'), Audit.action.like('event.%')))
    elif user.role == 'incident_responder':
        query = query.where(or_(Audit.actor_id == user.id, Audit.action.like('incident.%')))
    if action:
        query = query.where(Audit.action.ilike('%' + action.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%', escape='\\'))
    if days:
        query = query.where(Audit.created_at >= now() - timedelta(days=days))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(Audit.created_at.desc()).offset(offset).limit(100)).all()
    actor_ids = {a.actor_id for a in rows if a.actor_id}
    actors = {r[0]: r[1] for r in db.execute(select(User.id, User.email).where(User.id.in_(actor_ids))) if actor_ids}
    return {'items': [{**serial(a), 'actor_email': actors.get(a.actor_id)} for a in rows], 'total': total, 'offset': offset, 'limit': 100}


@app.get('/health/live')
def live():
    return {'status': 'alive'}


@app.get('/health/ready')
def ready(db: DBSession = DB):
    try:
        db.execute(text('SELECT 1'))
        redis.Redis.from_url(config.redis_url, socket_timeout=2).ping()
        httpx.get(config.search_url + '/_cluster/health', timeout=2).raise_for_status()
        return {'status': 'ready'}
    except Exception:
        raise HTTPException(503, 'Dependency unavailable') from None


@app.get('/api/v1/system/health')
def system_health(user=Depends(require('feed')), db: DBSession = DB):
    cache = redis.Redis.from_url(config.redis_url, decode_responses=True)
    return {'dependencies': ready(db), 'dispatcher': cache.get('health:dispatcher'), 'scheduler': cache.get('health:scheduler'),
            'outbox_pending': db.scalar(select(func.count()).select_from(Outbox).where(Outbox.delivered.is_(False)))}


@app.get('/metrics')
def metrics(db: DBSession = DB):
    cache = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    for service in ('dispatcher', 'scheduler'):
        try:
            raw = cache.get(f'health:{service}')
        except Exception:
            raw = None
        try:
            value = datetime.fromisoformat(raw).timestamp()
        except (TypeError, ValueError):
            value = 0
        heartbeat.labels(service).set(value)
    all_ready = 1
    for name, probe in (('postgresql', lambda: db.execute(text('SELECT 1'))),
                        ('redis', cache.ping),
                        ('elasticsearch', lambda: httpx.get(config.search_url + '/_cluster/health', timeout=2).raise_for_status())):
        try:
            probe()
            dependency_up.labels(name).set(1)
        except Exception:
            dependency_up.labels(name).set(0)
            all_ready = 0
    readiness_up.set(all_ready)
    try:
        outbox_pending.set(db.scalar(select(func.count()).select_from(Outbox).where(Outbox.delivered.is_(False))) or 0)
    except Exception:
        outbox_pending.set(float('nan'))
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.websocket('/api/v1/ws')
async def websocket(ws: WebSocket):
    if ws.headers.get('origin') not in (None, config.origin):
        await ws.close(code=1008)
        return
    await ws.accept()
    cache = aioredis.from_url(config.redis_url, socket_connect_timeout=2, socket_timeout=2)
    pubsub = cache.pubsub()
    identity, accepted, incoming = None, False, None
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=5)
        if len(raw) > 16384:
            raise HTTPException(413, 'WebSocket authentication message too large')
        hello = Hello.model_validate_json(raw)
        token, channels = hello.access_token, list(dict.fromkeys(hello.channels))
        identity, role = await run_in_threadpool(authenticate_ws, token, channels)
        accepted = True
        await pubsub.subscribe(event_channel())
        await ws.send_json({'status': 'subscribed', 'channels': channels})
        incoming = asyncio.create_task(ws.receive())
        while True:
            if incoming.done():
                if incoming.result()['type'] == 'websocket.disconnect':
                    raise WebSocketDisconnect()
                incoming = asyncio.create_task(ws.receive())
            await run_in_threadpool(authenticate_ws, token)
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
            if message:
                payload = json.loads(message['data'])
                if payload['channel'] in channels and (not payload.get('recipient_id') or payload['recipient_id'] == identity or role in ('administrator', 'incident_responder')):
                    await ws.send_json(payload)
            await asyncio.sleep(.05)
    except (WebSocketDisconnect, HTTPException, ValueError, KeyError, asyncio.TimeoutError, redis.RedisError, OperationalError):
        try:
            await ws.close(code=1008)
        except RuntimeError:
            pass
    finally:
        # Client disconnect cancellation must not skip the authentication audit.
        with anyio.CancelScope(shield=True):
            if incoming is not None:
                incoming.cancel()
                await asyncio.gather(incoming, return_exceptions=True)
            try:
                await run_in_threadpool(record_disconnect, identity, accepted)
            except OperationalError:
                logger.error(json.dumps({'event': 'websocket_audit_unavailable'}))
            await pubsub.aclose()
            await cache.aclose()
