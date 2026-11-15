"""Validate provider data before it can affect scores, caches or maps."""
from datetime import datetime, timezone
from math import isfinite


def number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not low <= value <= high:
        raise ValueError('Provider numeric field out of bounds')
    return value


def normalize_result(provider, payload, at):
    result = {'provider': provider, 'status': 'ok', 'observed_at': at.isoformat()}
    if provider == 'virustotal':
        attrs = payload['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        if not isinstance(stats, dict):
            raise ValueError('Invalid engine verdicts')
        counts = [number(v, 0, 100000) for v in stats.values()]
        if any(int(v) != v for v in counts):
            raise ValueError('Engine counts must be integers')
        total, malicious = sum(counts), stats.get('malicious', 0)
        categories = attrs.get('categories', {})
        if not isinstance(categories, dict) or any(not isinstance(v, str) for v in categories.values()):
            raise ValueError('Invalid domain categories')
        created = attrs.get('creation_date')
        age = None
        if created is not None:
            number(created, 0, at.timestamp())
            age = (at - datetime.fromtimestamp(created, timezone.utc)).total_seconds()
        result.update(engine_malicious=malicious, engine_total=total, verdict_ratio=malicious / total if total else None,
            categories=categories, creation_date=created, reputation=attrs.get('reputation'),
            newly_registered=age < 30 * 86400 if age is not None else None,
            known_phishing=any('phish' in v.lower() for v in categories.values()) if categories else None,
            normalized_reputation=round(100 * malicious / total) if total else None)
    elif provider == 'abuseipdb':
        attrs = payload['data']
        confidence = number(attrs['abuseConfidenceScore'], 0, 100)
        reports = number(attrs['totalReports'], 0, 10**12)
        result.update(abuse_confidence=confidence, total_reports=reports, owner=attrs.get('isp'), normalized_reputation=confidence)
    elif provider == 'ipwhois':
        if payload.get('success') is not True:
            raise ValueError('Geolocation provider has no result')
        latitude, longitude = number(payload['latitude'], -90, 90), number(payload['longitude'], -180, 180)
        connection = payload.get('connection') or {}
        result.update(latitude=latitude, longitude=longitude, country=payload.get('country_code'),
            asn=connection.get('asn'), owner=connection.get('org'))
    else:
        raise ValueError('Unknown enrichment provider')
    return result
