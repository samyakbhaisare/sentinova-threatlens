import json
from datetime import timedelta

import pytest
import stix2
from sqlalchemy import func, select, text, update

from app.correlation import correlate
from app.intelligence import ingest
from app.models import Alert, AlertRule, Audit, EventObservable, Feed, Incident, IncidentLink, Indicator, Provenance, SecurityEvent, Sighting, Timeline, now
from app.reporting import csv_export, generate, report_path, stix_export

pytestmark = pytest.mark.integration


def sample(db):
    feed=Feed(name='CONTROLLED TEST FEED',adapter='json',url='internal',reliability=100,ttl_days=30)
    db.add(feed);db.flush()
    return ingest(db,feed,{'type':'ip','value':'192.0.2.9','confidence':100}),feed


def test_deduplication_provenance_and_reverse_correlation(db,monkeypatch):
    ioc,feed=sample(db)
    same=ingest(db,feed,{'type':'ip','value':'192.0.2.9','confidence':80})
    other=Feed(name='CONTROLLED OVERLAP',adapter='json',url='internal',reliability=50,ttl_days=30)
    db.add(other);db.flush()
    merged=ingest(db,other,{'type':'ip','value':'192.0.2.9','confidence':50})
    assert ioc.id==same.id==merged.id
    assert db.scalar(select(func.count()).select_from(Provenance).where(Provenance.indicator_id==ioc.id))==2
    restricted=ingest(db,feed,{'type':'ip','value':'192.0.2.9','tlp':'amber'})
    assert restricted.tlp=='amber'
    assert ingest(db,other,{'type':'ip','value':'192.0.2.9','tlp':'clear'}).tlp=='amber'
    event=SecurityEvent(source='controlled',external_id='one',occurred_at=now(),asset='test-host',observables=[{'type':'ip','value':ioc.value}],digest='test',controlled_test=True)
    db.add(event);db.flush()
    db.add(EventObservable(event_id=event.id,type=ioc.type,value=ioc.value))
    # Isolate from rules left in the shared isolated test database by other suites.
    db.execute(update(AlertRule).values(enabled=False))
    db.add(AlertRule(name='Test rule',min_score=70,min_sightings=1))
    db.flush()
    monkeypatch.setattr('app.intelligence.now',lambda:ioc.last_seen)
    correlate(db,event=event);correlate(db,indicator=ioc)
    db.flush()
    assert db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == ioc.id))==1
    assert db.scalar(select(func.count()).select_from(Alert).where(Alert.indicator_id == ioc.id))==1
    assert ioc.score==87


def test_auth_rotation_reuse_logout_and_roles(client,accounts):
    admin,headers,password=accounts['administrator']
    result=client.post('/api/v1/auth/login',json={'email':admin.email,'password':password})
    assert result.status_code==200
    old=client.cookies.get('refresh_token')
    rotated=client.post('/api/v1/auth/refresh')
    assert rotated.status_code==200
    assert old!=client.cookies.get('refresh_token')
    client.cookies.set('refresh_token',old)
    assert client.post('/api/v1/auth/refresh').status_code==401
    assert client.get('/api/v1/users',headers={'Authorization':'Bearer '+rotated.json()['access_token']}).status_code==401
    for role,(_,auth,_) in accounts.items():
        if role=='administrator':
            continue
        assert client.get('/api/v1/users',headers=auth).status_code==403
        assert client.get('/api/v1/search',headers=auth).status_code==403 if role=='executive' else True
    soc,auth,password=accounts['soc_analyst']
    assert client.post('/api/v1/auth/logout',headers=auth).status_code==200
    assert client.get('/api/v1/auth/me',headers=auth).status_code==401


def test_event_alert_incident_report_flow(client,accounts,db):
    admin,auth,_=accounts['administrator'];analyst,analyst_auth,_=accounts['soc_analyst']
    ioc,feed=sample(db)
    rule=client.post('/api/v1/alert-rules',headers=auth,json={'name':'Controlled test rule','min_score':70,'min_sightings':1})
    assert rule.status_code==201
    event={'source':'controlled-e2e','external_id':'event-1','occurred_at':now().isoformat(),'asset':'test-workstation','observables':[{'type':'ip','value':ioc.value}],'controlled_test':True}
    assert client.post('/api/v1/events',headers=auth,json=event).status_code==201
    assert client.post('/api/v1/events',headers=auth,json=event).json()['replayed']
    assert client.post('/api/v1/events',headers=auth,json={**event,'asset':'different'}).status_code==409
    alert=client.get('/api/v1/alerts',headers=analyst_auth).json()['items'][0]
    assert client.patch('/api/v1/alerts/'+alert['id'],headers=analyst_auth,json={'state':'closed'}).status_code==409
    for state in ('acknowledged','in-progress','resolved','closed'):
        assert client.patch('/api/v1/alerts/'+alert['id'],headers=analyst_auth,json={'state':state,'assignee_id':analyst.id}).status_code==200
    incident=client.post('/api/v1/incidents',headers=analyst_auth,json={'title':'Controlled test investigation','indicator_id':ioc.id,'alert_id':alert['id']})
    assert incident.status_code==201
    identifier=incident.json()['id']
    timeline=client.get('/api/v1/incidents/'+identifier+'/timeline',headers=analyst_auth).json()
    assert len(timeline['items'])==2
    assert client.patch('/api/v1/incidents/'+identifier,headers=analyst_auth,json={'state':'resolved'}).status_code==403
    assert client.post('/api/v1/incidents/'+identifier+'/timeline',headers=analyst_auth,json={'text':'Evidence reviewed'}).status_code==201
    report=client.post('/api/v1/reports',headers=analyst_auth,json={'title':'Controlled report','incident_id':identifier})
    from app.models import Report
    row=db.get(Report,report.json()['id']);generate(db,row);db.flush()
    assert report_path(row.id).read_bytes().startswith(b'%PDF')
    executive,executive_auth,_=accounts['executive']
    assert client.get('/api/v1/reports/'+row.id+'/download',headers=executive_auth).status_code==403
    assert client.get('/api/v1/export/stix',headers=executive_auth).status_code==403
    assert db.scalar(select(func.count()).select_from(Audit))>=9


def test_exports_all_types_and_tlp(client,accounts,db):
    ioc,feed=sample(db)
    values=[('domain','example.org'),('url','https://example.org/'),('hash_md5','a'*32),('hash_sha1','b'*40),('hash_sha256','c'*64),('email','a@example.org'),('cve','CVE-2026-1234'),('ip','2001:db8::1')]
    rows=[ioc]+[ingest(db,feed,{'type':kind,'value':value}) for kind,value in values]
    bundle=stix_export(rows)
    assert stix2.parse(json.dumps(bundle)).type=='bundle'
    assert len(csv_export(rows).splitlines())==10
    ioc.tlp='red';db.flush()
    response=client.get('/api/v1/export/csv?audience=internal',headers=accounts['administrator'][1])
    assert response.status_code==200 and '192.0.2.9' not in response.text


def test_lockout_validation_context_and_layout(client,accounts,db):
    user,auth,password=accounts['soc_analyst']
    assert client.post('/api/v1/auth/login',json={'email':user.email,'password':'wrong'}).status_code==401
    assert client.post('/api/v1/auth/login',json={'email':user.email,'password':password}).status_code==401
    ioc,_=sample(db)
    assert client.patch('/api/v1/indicators/'+ioc.id,headers=auth,json={'status':'whitelisted'}).status_code==403
    assert client.patch('/api/v1/indicators/'+ioc.id,headers=auth,json={'tags':['investigate'],'techniques':['T1059']}).status_code==200
    assert client.patch('/api/v1/indicators/'+ioc.id,headers=auth,json={'techniques':['Tbad']}).status_code==422
    assert client.patch('/api/v1/layout',headers=auth,json={'widgets':['map','metrics']}).status_code==200
    assert client.get('/api/v1/auth/me',headers=auth).json()['layout']==['map','metrics']
    assert client.get('/api/v1/auth/me',headers=accounts['executive'][1]).json()['layout']!=['map','metrics']


def test_immutable_evidence_role(db):
    # Test role grants must be installed by the integration runner.
    grants=db.execute(text("SELECT has_table_privilege(current_user, 'audit_log', 'UPDATE'), has_table_privilege(current_user, 'incident_timeline', 'DELETE')")).one()
    assert grants==(False,False)
