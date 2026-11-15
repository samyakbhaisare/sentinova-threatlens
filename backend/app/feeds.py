"""Feed transports only fetch configured intelligence endpoints, never IOC URLs."""
import csv
import io
import ipaddress
import json
import re
import socket
from time import monotonic
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .config import settings
from .retry import DeferredRequest, retry_after

CATALOG = [
    ('CISA KEV', 'cisa', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 21600, 90),
    ('Feodo Tracker', 'feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', 3600, 80),
    ('Blocklist.de FTP', 'ip_lines', 'https://lists.blocklist.de/lists/ftp.txt', 3600, 60),
    ('Emerging Threats', 'ip_lines', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 86400, 60),
    ('CINS Army', 'ip_lines', 'https://cinsscore.com/list/ci-badguys.txt', 86400, 60),
    ('IPsum level 8', 'ip_lines', 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt', 86400, 50),
]
ADAPTERS = {'cisa', 'feodo', 'url_lines', 'ip_lines', 'json', 'csv', 'stix', 'taxii', 'otx', 'urlhaus', 'threatfox', 'malwarebazaar'}


def validate_url(url):
    parsed = urlsplit(url)
    allowed = set(settings().feed_hosts.split(',')) | {'lists.blocklist.de', 'rules.emergingthreats.net', 'cinsscore.com'}
    if parsed.scheme != 'https' or parsed.hostname not in allowed or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Feed URL must use HTTPS on an operator-allowlisted host')
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError('Non-public feed destination denied')


def fetch(url, *, headers=None, method='GET', body=None, form=None, max_bytes=32 * 1024 * 1024, max_seconds=90):
    deadline = monotonic() + max_seconds
    validate_url(url)
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        with client.stream(method, url, headers=headers, json=body, data=form) as response:
            if response.status_code in (429, 503):
                raise DeferredRequest(retry_after(response.headers.get('Retry-After')), 'feed_rate_limited')
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                if monotonic() > deadline:
                    raise ValueError('Feed transfer deadline exceeded')
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError('Feed exceeds configured byte limit')
                chunks.append(chunk)
            return b''.join(chunks).decode('utf-8-sig')


def stix_records(objects):
    import stix2
    markings = {stix2.TLP_WHITE.id: 'clear', stix2.TLP_GREEN.id: 'green', stix2.TLP_AMBER.id: 'amber', stix2.TLP_RED.id: 'red'}
    for obj in objects:
        if obj.get('type') == 'marking-definition' and obj.get('definition_type') == 'tlp':
            marking = obj.get('definition', {}).get('tlp')
            if marking in ('white', 'clear', 'green', 'amber', 'red'):
                markings[obj['id']] = 'clear' if marking == 'white' else marking
    mapping = {'ipv4-addr:value': 'ip', 'ipv6-addr:value': 'ip', 'domain-name:value': 'domain', 'url:value': 'url',
               "file:hashes.'MD5'": 'hash_md5', "file:hashes.'SHA-1'": 'hash_sha1', "file:hashes.'SHA-256'": 'hash_sha256', 'email-addr:value': 'email'}
    for obj in objects:
        levels = {'clear': 0, 'green': 1, 'amber': 2, 'red': 3}
        if obj.get('granular_markings'):
            raise ValueError('Granular STIX handling requires explicit mapping; ingestion denied')
        references = obj.get('object_marking_refs', [])
        if any(ref not in markings for ref in references):
            raise ValueError('Unknown STIX handling marking; ingestion denied')
        tlp = max((markings[ref] for ref in references), key=levels.get, default='clear')
        if obj.get('type') == 'vulnerability' and obj.get('name', '').upper().startswith('CVE-'):
            yield {'type': 'cve', 'value': obj['name'], 'confidence': obj.get('confidence', 0), 'reference': obj['id'], 'tlp': tlp}
        elif obj.get('type') == 'indicator':
            match = re.fullmatch(r"\[([^=]+)\s*=\s*'((?:\\.|[^'])*)'\]", obj.get('pattern', ''))
            if not match or match[1].strip() not in mapping:
                raise ValueError('Unsupported compound STIX pattern; requires a single observable equality')
            yield {'type': mapping[match[1].strip()], 'value': match[2].replace("\\'", "'").replace('\\\\', '\\'), 'confidence': obj.get('confidence', 0), 'reference': obj['id'], 'tlp': tlp}


def parse(adapter, text):
    if adapter in ('ip_lines', 'url_lines'):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                yield {'type': 'ip' if adapter == 'ip_lines' else 'url', 'value': line.split()[0], 'category': 'phishing' if adapter == 'url_lines' else 'suspicious_infrastructure'}
        return
    if adapter == 'csv':
        yield from csv.DictReader(io.StringIO(text))
        return
    payload = json.loads(text)
    if adapter in ('urlhaus', 'malwarebazaar', 'threatfox') and payload.get('query_status') not in (None, 'ok', 'no_results', 'no_result'):
        raise ValueError('Provider rejected feed query')
    if adapter == 'cisa':
        for row in payload['vulnerabilities']:
            yield {'type': 'cve', 'value': row['cveID'], 'confidence': 100, 'category': 'exploited_vulnerability',
                   'last_seen': datetime.fromisoformat(row['dateAdded']).replace(tzinfo=timezone.utc)}
    elif adapter == 'feodo':
        for row in payload:
            yield {'type': 'ip', 'value': row['ip_address'], 'category': 'botnet_c2', 'confidence': 0}
    elif adapter in ('stix', 'taxii'):
        yield from stix_records(payload.get('objects', []))
    elif adapter == 'json':
        yield from payload if isinstance(payload, list) else payload['indicators']
    elif adapter == 'otx':
        mapping = {'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain', 'URL': 'url', 'FileHash-MD5': 'hash_md5', 'FileHash-SHA1': 'hash_sha1', 'FileHash-SHA256': 'hash_sha256', 'email': 'email', 'CVE': 'cve'}
        for pulse in payload['results']:
            for row in pulse.get('indicators', []):
                if row['type'] in mapping:
                    yield {'type': mapping[row['type']], 'value': row['indicator'], 'reference': pulse['id']}
    elif adapter == 'urlhaus':
        for row in payload.get('urls', []):
            yield {'type': 'url', 'value': row['url'], 'category': 'malware_distribution', 'reference': row.get('urlhaus_reference', '')}
    elif adapter == 'malwarebazaar':
        for row in payload.get('data', []):
            yield {'type': 'hash_sha256', 'value': row['sha256_hash'], 'category': 'malware'}
    elif adapter == 'threatfox':
        for row in payload.get('data', []):
            mapping = {'ip:port': 'ip', 'domain': 'domain', 'url': 'url', 'md5_hash': 'hash_md5', 'sha256_hash': 'hash_sha256'}
            if row['ioc_type'] in mapping:
                value = row['ioc'].rsplit(':', 1)[0] if row['ioc_type'] == 'ip:port' else row['ioc']
                yield {'type': mapping[row['ioc_type']], 'value': value, 'confidence': row.get('confidence_level', 0), 'category': row.get('threat_type', 'malware')}
    else:
        raise ValueError('Unknown feed adapter')


def poll(feed):
    secret = settings().secret(feed.secret_ref)
    if feed.secret_ref and not secret:
        raise ValueError('Missing credential secret reference')
    headers = {'User-Agent': 'Sentinova-ThreatLens/1.0'}
    if secret:
        headers['X-OTX-API-KEY' if feed.adapter == 'otx' else 'Auth-Key'] = secret
    url = feed.url
    if feed.adapter == 'taxii':
        headers['Accept'] = 'application/taxii+json;version=2.1'
        if secret:
            headers.pop('Auth-Key', None)
            headers['Authorization'] = 'Bearer ' + secret
    seen = set()
    for _ in range(100):
        if (urlsplit(url).scheme, urlsplit(url).hostname, urlsplit(url).port) != (urlsplit(feed.url).scheme, urlsplit(feed.url).hostname, urlsplit(feed.url).port):
            raise ValueError('Cross-origin pagination denied; credentials remain source-scoped')
        if url in seen:
            raise ValueError('Feed pagination loop')
        seen.add(url)
        body = {'query': 'get_iocs', 'days': 1} if feed.adapter == 'threatfox' else None
        form = {'query': 'get_recent', 'selector': 'time'} if feed.adapter == 'malwarebazaar' else None
        text = fetch(url, headers=headers, method='POST' if body or form else 'GET', body=body, form=form)
        yield from parse(feed.adapter, text)
        if feed.adapter not in ('taxii', 'otx'):
            return
        payload = json.loads(text)
        if feed.adapter == 'otx':
            url = payload.get('next')
        elif payload.get('more'):
            from urllib.parse import urlencode
            url = feed.url + ('&' if '?' in feed.url else '?') + urlencode({'next': payload['next']})
        else:
            return
        if not url:
            return
    raise ValueError('Pagination safety limit exceeded; feed not marked successful')
