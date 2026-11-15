"""Controlled STIX fixtures and SQLite storage tests; no measured production history."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.attack import coverage, parse_catalog, replace_mappings, synchronize
from app.models import AttackTechnique, Audit, Indicator, RiskSnapshot, TechniqueMapping
from app.risk import capture
from test_operations_routes import routes  # noqa: F401

AT = datetime(2026, 10, 28, 12, 15, tzinfo=timezone.utc)


def bundle(ids=('T1059','T1059.001')):
    return json.dumps({'type':'bundle','objects':[{'type':'attack-pattern','id':'attack-pattern--controlled-'+identifier,
        'name':'CONTROLLED reference '+identifier,'modified':'2026-07-01T00:00:00Z','description':'Controlled unit fixture',
        'external_references':[{'source_name':'mitre-attack','external_id':identifier}],
        'kill_chain_phases':[{'kill_chain_name':'mitre-attack','phase_name':'execution'}],
        'x_mitre_platforms':['Windows']} for identifier in ids]})


def test_reference_sync_resolves_assertions_and_tracks_retired_entries(routes):
    client, db, people, feed, domain, ip = routes
    domain.techniques=['T1059']; db.flush()
    replace_mappings(db, domain.id, domain.techniques); db.flush()
    assert db.get(AttackTechnique,'T1059').known is False
    count, checksum = synchronize(db,bundle()); db.flush()
    assert count==2 and len(checksum)==64
    result=coverage(db)
    mapped=next(row for row in result['items'] if row['technique_id']=='T1059')
    assert mapped['known'] and mapped['active_indicators']==1 and mapped['tactics']==['execution']
    assert result['observed_count']==1 and result['active_reference_count']==2
    synchronize(db,bundle(('T1059',))); db.flush()
    retired=next(row for row in coverage(db)['items'] if row['technique_id']=='T1059.001')
    assert not retired['catalog_present']
    assert db.scalar(select(func.count()).select_from(TechniqueMapping))==1


def test_malformed_reference_does_not_mutate_existing_catalog(routes):
    client, db, people, feed, domain, ip = routes
    synchronize(db,bundle()); db.flush()
    with pytest.raises(ValueError): synchronize(db,'{"type":"bundle","objects":[]}')
    assert coverage(db)['active_reference_count']==2
    bad=json.loads(bundle());bad['objects'][0]['external_references'][0]['external_id']='not-a-technique'
    with pytest.raises(ValueError):parse_catalog(json.dumps(bad))


def test_hourly_snapshot_preserves_actual_capture_and_never_rewrites_history(routes):
    client, db, people, feed, domain, ip = routes
    first=capture(db,AT);db.flush()
    assert first.data['risk_score']==50 and first.data['active_indicators']==2
    domain.score=100;db.flush()
    same=capture(db,AT+timedelta(minutes=20))
    assert same.id==first.id and same.data['risk_score']==50
    second=capture(db,AT+timedelta(hours=2));db.flush()
    assert second.data['risk_score']==65
    assert db.scalar(select(func.count()).select_from(RiskSnapshot))==2
    assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action=='risk.snapshot_captured'))==2


def test_empty_history_is_not_fabricated_and_access_roles_are_enforced(routes):
    client, db, people, feed, domain, ip = routes
    response=client.get('/api/v1/dashboard/risk-history',headers=people['executive'][1])
    assert response.json()['items']==[] and response.json()['backfilled'] is False
    assert client.post('/api/v1/dashboard/risk-snapshots',headers=people['executive'][1]).status_code==403
    assert client.post('/api/v1/attack/sync',headers=people['soc_analyst'][1]).status_code==403
    assert client.get('/api/v1/attack/coverage',headers=people['executive'][1]).status_code==403
    assert client.post('/api/v1/attack/sync',headers=people['security_engineer'][1]).status_code==202


def test_no_active_intelligence_has_unknown_risk_not_zero(routes):
    client, db, people, feed, domain, ip = routes
    domain.status=ip.status='expired';db.flush()
    snapshot=capture(db,AT)
    assert snapshot.data['risk_score'] is None and snapshot.data['active_indicators']==0
