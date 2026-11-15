import ipaddress
import json
import hashlib
from datetime import datetime, timedelta
from urllib.parse import quote

import httpx
import redis
from sqlalchemy import select

from .config import settings
from .intelligence import rescore
from .models import Enrichment, now
from .provider_results import normalize_result
from .retry import DeferredRequest, retry_after


def provider_request(provider, path, key, params=None):
    config = settings()
    cache = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    identity = json.dumps([provider, path, params or {}, hashlib.sha256(key.encode()).hexdigest()], sort_keys=True, separators=(',', ':'))
    cache_key = 'enrich:v2:' + hashlib.sha256(identity.encode()).hexdigest()
    cached = cache.get(cache_key)
    if cached:
        return json.loads(cached), True
    # Global provider budgets apply across workers; free-tier conservative defaults.
    bucket = f'provider-budget:{provider}'
    if not cache.set(bucket, '1', nx=True, ex=16 if provider == 'virustotal' else 2):
        raise DeferredRequest(max(1, cache.ttl(bucket)), 'provider_budget')
    base = {'virustotal': config.virustotal_base_url, 'abuseipdb': config.abuseipdb_base_url, 'ipwhois': config.ipwhois_base_url}[provider]
    headers = {'x-apikey': key} if provider == 'virustotal' else {'Key': key, 'Accept': 'application/json'} if provider == 'abuseipdb' else {}
    response = httpx.get(base + path, headers=headers, params=params, timeout=8, follow_redirects=False)
    if response.status_code in (429, 503):
        delay = retry_after(response.headers.get('Retry-After'))
        cache.setex(bucket, delay, '1')
        raise DeferredRequest(delay, 'provider_rate_limited')
    response.raise_for_status()
    data = normalize_result(provider, response.json(), now())
    cache.setex(cache_key, 3600, json.dumps(data))
    return data, False


def enrich(db, indicator):
    providers, results = [], []
    config = settings()
    if getattr(indicator, 'tlp', None) != 'clear':
        blocked = {'provider': 'policy', 'status': 'blocked', 'reason': 'External providers accept TLP:clear indicators only'}
        db.add(Enrichment(indicator_id=indicator.id, provider='policy', data=blocked, expires_at=now() + timedelta(hours=1)))
        return [blocked]
    if indicator.type == 'ip':
        if not ipaddress.ip_address(indicator.value).is_global:
            blocked = {'provider': 'policy', 'status': 'blocked', 'reason': 'External enrichment of non-public addresses is prohibited'}
            db.add(Enrichment(indicator_id=indicator.id, provider='policy', data=blocked, expires_at=now() + timedelta(hours=1)))
            return [blocked]
        providers.append(('abuseipdb', 'check', 'abuseipdb_key', {'ipAddress': indicator.value, 'maxAgeInDays': 90}))
        if config.geolocation_enabled:
            providers.append(('ipwhois', quote(indicator.value, safe=''), '', None))
        else:
            blocked = {'provider': 'ipwhois', 'status': 'blocked', 'reason': 'Enable geolocation after confirming usage entitlement'}
            db.add(Enrichment(indicator_id=indicator.id, provider='ipwhois', data=blocked, expires_at=now() + timedelta(hours=1)))
            results.append(blocked)
    if indicator.type in ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256'):
        resource = 'ip_addresses' if indicator.type == 'ip' else 'domains' if indicator.type == 'domain' else 'files'
        providers.append(('virustotal', resource + '/' + quote(indicator.value, safe=''), 'virustotal_key', None))
    for provider, path, ref, params in providers:
        key = config.secret(ref) if ref else ''
        if ref and not key:
            blocked = {'provider': provider, 'status': 'blocked', 'reason': 'Credential not configured'}
            results.append(blocked)
            db.add(Enrichment(indicator_id=indicator.id, provider=provider, data=blocked, expires_at=now() + timedelta(minutes=5)))
            continue
        try:
            normalized, cached = provider_request(provider, path, key, params)
            data = {**normalized, 'cached': cached}
            if data.get('normalized_reputation') is not None:
                indicator.reputation = max(indicator.reputation, data['normalized_reputation'])
            db.add(Enrichment(indicator_id=indicator.id, provider=provider, data=data, expires_at=datetime.fromisoformat(data['observed_at']) + timedelta(hours=1)))
            results.append(data)
        except DeferredRequest as exc:
            deferred = {'provider': provider, 'status': 'deferred', 'retry_after': exc.seconds, 'reason': exc.reason}
            results.append(deferred)
            db.add(Enrichment(indicator_id=indicator.id, provider=provider, data=deferred, expires_at=now() + timedelta(seconds=exc.seconds)))
        except (httpx.HTTPError, ValueError, KeyError, TypeError, redis.RedisError) as exc:
            transient = isinstance(exc, (httpx.TransportError, redis.RedisError)) or (isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500)
            failure = {'provider': provider, 'status': 'deferred' if transient else 'error', 'reason': type(exc).__name__}
            if transient:
                failure['retry_after'] = 30
            results.append(failure)
            db.add(Enrichment(indicator_id=indicator.id, provider=provider, data=failure, expires_at=now() + timedelta(minutes=5)))
    rescore(db, indicator)
    return results


def latest(db, identifier):
    rows = db.scalars(select(Enrichment).where(Enrichment.indicator_id == identifier).order_by(Enrichment.created_at.desc())).all()
    found = {}
    for row in rows:
        if row.provider not in found:
            found[row.provider] = {**row.data, 'expires_at': row.expires_at.isoformat(), 'stale': row.expires_at <= now()}
    return list(found.values())
