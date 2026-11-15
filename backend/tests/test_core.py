from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.correlation import rule_matches
from app.feeds import parse, stix_records, validate_url
from app.intelligence import canonical
from app.scoring import score

AT = datetime(2026, 7, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize('rep,confidence,days,sightings,expected', [
    (100, 100, 0, 10, 100), (0, 0, 0, 0, 20), (None, None, 30, 0, 0),
    (80, 60, 15, 2, 59), (200, -5, 100, 100, 50), (50, 50, -1, 0, 53),
    (0, 0, 60, -1, 0), (100, 100, 30, 0, 65),
])
def test_exact_scores(rep, confidence, days, sightings, expected):
    actual, breakdown = score(rep, confidence, AT-timedelta(days=days), sightings, AT)
    assert actual == expected
    assert sum(breakdown['weights'].values()) == pytest.approx(1)


def test_score_nonfinite_and_naive_boundary():
    with pytest.raises(ValueError):
        score(float('nan'), 0, AT, 0, AT)
    assert score(100, 100, AT.replace(tzinfo=None), 0, AT)[0] == 85


@pytest.mark.parametrize('kind,value,expected', [
    ('ip', '2001:0db8::1', '2001:db8::1'), ('ip', '192.0.2.1', '192.0.2.1'),
    ('domain', 'EXAMPLE.ORG.', 'example.org'), ('domain', 'bücher.de', 'xn--bcher-kva.de'),
    ('url', 'HTTPS://Example.org:443/a?q=x#f', 'https://example.org/a?q=x'),
    ('url', 'http://[2001:db8::1]:8080', 'http://[2001:db8::1]:8080/'),
    ('url', 'http://192.0.2.1:80', 'http://192.0.2.1/'),
    ('hash_md5', 'A'*32, 'a'*32), ('hash_sha1', 'B'*40, 'b'*40), ('hash_sha256', 'C'*64, 'c'*64),
    ('email', 'Analyst@EXAMPLE.ORG', 'Analyst@example.org'), ('cve', 'cve-2026-12345', 'CVE-2026-12345'),
])
def test_canonical(kind, value, expected):
    assert canonical(kind, value) == expected


@pytest.mark.parametrize('kind,value', [('ip','999.1.1.1'), ('domain','-bad.org'), ('domain','localhost'),
    ('url','file:///etc/passwd'), ('url','https://user:pass@example.org'), ('hash_sha256','abcd'),
    ('email','bad@@example.org'), ('cve','CVE-xyz'), ('bad','x'), ('domain',''), ('domain','a\nb.org')])
def test_reject_invalid(kind, value):
    with pytest.raises(ValueError):
        canonical(kind, value)


def test_normalization_formats():
    assert list(parse('csv','type,value\ndomain,example.org\n')) == [{'type':'domain','value':'example.org'}]
    assert list(parse('json','[{"type":"ip","value":"192.0.2.1"}]'))[0]['type']=='ip'
    assert list(parse('ip_lines','# comment\n192.0.2.1\t5\n'))[0]['value']=='192.0.2.1'
    assert list(parse('url_lines','https://example.org/\n'))[0]['category']=='phishing'
    assert list(parse('cisa','{"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-07-01"}]}'))[0]['confidence']==100
    assert list(parse('feodo','[{"ip_address":"192.0.2.1"}]'))[0]['category']=='botnet_c2'
    assert list(stix_records([{'id':'indicator--test', 'type':'indicator','pattern':"[domain-name:value = 'example.org']"}]))[0]['value']=='example.org'
    assert list(stix_records([{'id':'vulnerability--test','type':'vulnerability','name':'CVE-2026-1234'}]))[0]['type']=='cve'
    with pytest.raises(ValueError):
        list(stix_records([{'type':'indicator','pattern':"[domain-name:value LIKE '%example%']"}]))
    with pytest.raises(ValueError):
        list(parse('unsupported','{}'))


def test_provider_formats():
    assert list(parse('otx','{"results":[{"id":"p1","indicators":[{"type":"IPv4","indicator":"192.0.2.1"}]}]}'))[0]['reference']=='p1'
    assert list(parse('urlhaus','{"urls":[{"url":"https://example.org"}]}'))[0]['type']=='url'
    assert list(parse('malwarebazaar','{"data":[{"sha256_hash":"abc"}]}'))[0]['type']=='hash_sha256'
    assert list(parse('threatfox','{"data":[{"ioc_type":"ip:port","ioc":"192.0.2.1:443"}]}'))[0]['value']=='192.0.2.1'


@pytest.mark.parametrize('url', ['http://www.cisa.gov/x','https://127.0.0.1/x','https://evil.example/x','https://user:password@www.cisa.gov/x','https://www.cisa.gov:444/x'])
def test_ssrf_rejection(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_rules_all_filters():
    ioc=SimpleNamespace(status='active',score=80,category='phishing')
    rule=SimpleNamespace(enabled=True,min_score=70,min_sightings=1,category='phishing',feed_id='feed')
    assert rule_matches(rule,ioc,1,{'feed'})
    assert not rule_matches(rule,ioc,0,{'feed'})
    assert not rule_matches(rule,ioc,1,{'other'})
    ioc.category='malware'
    assert not rule_matches(rule,ioc,1,{'feed'})
    ioc.category='phishing'; ioc.status='whitelisted'
    assert not rule_matches(rule,ioc,1,{'feed'})
    ioc.status='active'; ioc.score=69
    assert not rule_matches(rule,ioc,1,{'feed'})
    ioc.score=80; rule.enabled=False
    assert not rule_matches(rule,ioc,1,{'feed'})
