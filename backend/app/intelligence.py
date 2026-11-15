import ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert

from .models import Indicator, Outbox, Provenance, Sighting, now, uid
from .scoring import score
from .config import settings

TYPES = ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'cve')
TLP_LEVELS = {'clear': 0, 'green': 1, 'amber': 2, 'red': 3}


def record_metadata(record):
    tlp = record.get('tlp', 'clear').lower()
    if tlp not in TLP_LEVELS:
        raise ValueError('Unknown TLP marking')
    observed = record.get('last_seen') or now()
    if isinstance(observed, str):
        observed = datetime.fromisoformat(observed.replace('Z', '+00:00'))
    if observed.tzinfo is None:
        raise ValueError('Source timestamp must contain a timezone')
    return tlp, min(observed.astimezone(timezone.utc), now())


def domain(value):
    value = value.rstrip('.').encode('idna').decode().lower()
    if len(value) > 253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError('Invalid domain')
    return value


def canonical(kind, value):
    if not isinstance(kind, str) or not isinstance(value, str):
        raise ValueError('Indicator type and value must be strings')
    value = value.strip()
    if not value or len(value.encode('utf-8')) > 2048 or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid indicator length or control characters')
    if kind == 'ip':
        return str(ipaddress.ip_address(value))
    if kind == 'domain':
        return domain(value)
    if kind == 'url':
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Only HTTP(S) IOC URLs without credentials are supported')
        try:
            host = str(ipaddress.ip_address(parsed.hostname))
            host = f'[{host}]' if ':' in host else host
        except ValueError:
            host = domain(parsed.hostname)
        port = parsed.port
        if port and (parsed.scheme.lower(), port) not in [('http', 80), ('https', 443)]:
            host += f':{port}'
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or '/', parsed.query, ''))
    if kind.startswith('hash_'):
        lengths = {'hash_md5': 32, 'hash_sha1': 40, 'hash_sha256': 64}
        if kind not in lengths or not re.fullmatch('[0-9a-fA-F]{' + str(lengths[kind]) + '}', value):
            raise ValueError('Invalid file hash')
        return value.lower()
    if kind == 'email':
        local, sep, host = value.rpartition('@')
        if not sep or not local or len(local) > 64 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
            raise ValueError('Invalid email')
        return local + '@' + domain(host)
    if kind == 'cve' and re.fullmatch(r'CVE-\d{4}-\d{4,}', value.upper()):
        return value.upper()
    raise ValueError('Unsupported or invalid indicator type')


def rescore(db, indicator):
    count = db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == indicator.id))
    indicator.score, indicator.breakdown = score(indicator.reputation, indicator.confidence, indicator.last_seen, count, now())
    db.add(Outbox(topic='indicators', object_id=indicator.id))


def ingest(db, feed, record):
    kind, value = record['type'], canonical(record['type'], record['value'])
    confidence = max(0, min(100, int(record.get('confidence', 0))))
    tlp, observed = record_metadata(record)
    values = dict(id=uid(), type=kind, value=value, confidence=confidence, reputation=feed.reliability, tlp=tlp,
                  category=str(record.get('category', 'unknown'))[:100], first_seen=observed, last_seen=observed,
                  expires_at=observed + timedelta(days=feed.ttl_days))
    stmt = insert(Indicator).values(**values).on_conflict_do_update(index_elements=['type', 'value'], set_={
        'first_seen': func.least(Indicator.first_seen, observed),
        'last_seen': func.greatest(Indicator.last_seen, observed),
        'expires_at': func.greatest(Indicator.expires_at, values['expires_at']),
        'confidence': func.greatest(Indicator.confidence, confidence),
        'tlp': case((case(TLP_LEVELS, value=Indicator.tlp) < TLP_LEVELS[tlp], tlp), else_=Indicator.tlp),
        'reputation': func.greatest(Indicator.reputation, feed.reliability), 'updated_at': now(),
        'version': Indicator.version + 1,
    }).returning(Indicator.id)
    identifier = db.scalar(stmt)
    db.execute(insert(Provenance).values(id=uid(), indicator_id=identifier, feed_id=feed.id, confidence=confidence, tlp=tlp,
        reference=str(record.get('reference', feed.url))[:2048], last_seen=observed).on_conflict_do_update(
        index_elements=['indicator_id', 'feed_id'], set_={'last_seen': func.greatest(Provenance.last_seen, observed), 'confidence': confidence,
            'tlp': case((case(TLP_LEVELS, value=Provenance.tlp) < TLP_LEVELS[tlp], tlp), else_=Provenance.tlp),
            'reference': str(record.get('reference', feed.url))[:2048]}))
    indicator = db.get(Indicator, identifier, populate_existing=True)
    rescore(db, indicator)
    from .security import audit
    audit(db, None, 'indicator.ingested', identifier, {'feed_id': feed.id, 'confidence': confidence,
        'source_observed_at': observed.isoformat(), 'tlp': tlp, 'created': identifier == values['id']})
    if settings().automatic_enrichment and identifier == values['id'] and kind in ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256'):
        db.add(Outbox(topic='indicator.enrich', object_id=identifier))
    return indicator
