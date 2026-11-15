"""Offline route/ORM tests using SQLite solely as a test double.

These exercise real handlers and persistence, not PostgreSQL locks, triggers or services.
"""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Alert, AlertRule, Audit, Feed, Incident, Indicator, Outbox, Timeline, User, now
from app.security import issue


@pytest.fixture
def routes():
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db=sessionmaker(engine,expire_on_commit=False)()
    people={}
    for role in ('administrator','security_engineer','incident_responder','soc_analyst','threat_hunter','executive'):
        user=User(name='CONTROLLED '+role,email=role+'@example.org',role=role,password_hash='not-used-by-this-test')
        db.add(user);db.flush()
        token,_=issue(db,user)
        people[role]=(user,{'Authorization':'Bearer '+token})
    feed=Feed(name='CONTROLLED source',adapter='json',url='internal',enabled=False)
    domain=Indicator(type='domain',value='controlled.example.org',score=70,confidence=50,reputation=70,expires_at=now()-timedelta(days=1))
    ip=Indicator(type='ip',value='192.0.2.1',score=30,expires_at=now()+timedelta(days=1))
    db.add_all([feed,domain,ip]);db.commit()
    def override():
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
    app.dependency_overrides[get_db]=override
    with TestClient(app) as client:
        yield client,db,people,feed,domain,ip
    app.dependency_overrides.clear();db.close();engine.dispose()


def test_rule_editor_authorization_clear_filters_and_disable(routes):
    client,db,people,feed,domain,ip=routes
    admin=people['administrator'][1]
    response=client.post('/api/v1/alert-rules',headers=admin,json={'name':'Controlled rule','feed_id':feed.id,'recipient_id':people['soc_analyst'][0].id})
    assert response.status_code==201
    identifier=response.json()['id']
    assert client.patch('/api/v1/alert-rules/'+identifier,headers=people['soc_analyst'][1],json={'enabled':False}).status_code==403
    result=client.patch('/api/v1/alert-rules/'+identifier,headers=admin,json={'enabled':False,'feed_id':None,'recipient_id':None,'min_score':85})
    assert result.status_code==200 and result.json()['enabled'] is False and result.json()['feed_id'] is None
    assert client.patch('/api/v1/alert-rules/'+identifier,headers=admin,json={'min_score':None}).status_code==422
    assert client.patch('/api/v1/alert-rules/'+identifier,headers=admin,json={'recipient_id':people['executive'][0].id}).status_code==422
    history=db.scalars(select(Audit).where(Audit.action=='rule.updated')).all()
    assert len(history)==1 and history[0].data['data']['before']['min_score']==70


def test_lifecycle_requires_new_ttl_and_creates_history(routes):
    client,db,people,feed,domain,ip=routes
    path='/api/v1/indicators/'+domain.id
    assert client.patch(path,headers=people['soc_analyst'][1],json={'status':'expired'}).status_code==403
    assert client.patch(path,headers=people['incident_responder'][1],json={'notes':'outside context'}).status_code==403
    assert client.patch(path,headers=people['administrator'][1],json={'status':'active'}).status_code==422
    result=client.patch(path,headers=people['administrator'][1],json={'status':'active','ttl_days':7,'tlp':'amber'})
    assert result.status_code==200 and result.json()['tlp']=='amber'
    history=client.get(path+'/history',headers=people['soc_analyst'][1]).json()['items']
    assert len(history)==1 and 'expires_at' in history[0]['data']['data']['before']
    assert db.scalars(select(Outbox).where(Outbox.object_id==domain.id)).first()


def test_relationship_and_incident_link_context(routes):
    client,db,people,feed,domain,ip=routes
    analyst,auth=people['soc_analyst']
    response=client.post('/api/v1/indicators/'+domain.id+'/relationships',headers=auth,json={'target_id':ip.id,'kind':'resolves-to'})
    assert response.status_code==201
    assert client.post('/api/v1/indicators/'+ip.id+'/relationships',headers=auth,json={'target_id':domain.id,'kind':'resolves-to'}).status_code==422
    assert client.post('/api/v1/indicators/'+domain.id+'/relationships',headers=auth,json={'target_id':domain.id,'kind':'related-to'}).status_code==422
    incident=client.post('/api/v1/incidents',headers=auth,json={'title':'CONTROLLED investigation','indicator_id':domain.id}).json()
    path='/api/v1/incidents/'+incident['id']
    assert client.post(path+'/links',headers=people['threat_hunter'][1],json={'indicator_id':ip.id}).status_code==403
    assert client.post(path+'/links',headers=auth,json={'indicator_id':ip.id}).status_code==201
    assert client.post(path+'/links',headers=auth,json={'indicator_id':ip.id}).json()['replayed'] is True
    assert client.patch('/api/v1/indicators/'+domain.id,headers=people['incident_responder'][1],json={'notes':'Contextual response'}).status_code==200
    timeline=client.get(path+'/timeline',headers=auth).json()['items']
    assert any(item['kind']=='indicator_updated' for item in timeline)
    assert client.patch(path,headers=people['administrator'][1],json={'state':'closed'}).status_code==409
    assert client.patch(path,headers=people['administrator'][1],json={'state':'resolved'}).status_code==200


def test_alert_history_routing_and_explicit_unassignment(routes):
    client,db,people,feed,domain,ip=routes
    analyst,auth=people['soc_analyst']
    rule=AlertRule(name='CONTROLLED routed',recipient_id=analyst.id)
    db.add(rule);db.flush()
    alert=Alert(indicator_id=domain.id,rule_id=rule.id,score=70,recipient_id=analyst.id,assignee_id=analyst.id)
    db.add(alert);db.commit()
    path='/api/v1/alerts/'+alert.id
    assert client.patch(path,headers=auth,json={'state':'acknowledged','assignee_id':None}).json()['assignee_id'] is None
    assert client.get(path+'/history',headers=people['threat_hunter'][1]).status_code==403
    history=client.get(path+'/history',headers=auth).json()['items']
    assert history[0]['data']['data']['before']['state']=='new'
    assert history[0]['data']['data']['after']['state']=='acknowledged'


def test_existing_incident_link_does_not_falsely_acknowledge_a_different_alert(routes):
    client,db,people,feed,domain,ip=routes
    owner,auth=people['soc_analyst']
    incident=client.post('/api/v1/incidents',headers=auth,json={'title':'CONTROLLED linked alerts','indicator_id':ip.id}).json()
    rules=[AlertRule(name='CONTROLLED rule one'),AlertRule(name='CONTROLLED rule two')]
    db.add_all(rules);db.flush()
    alerts=[Alert(indicator_id=ip.id,rule_id=rule.id,score=50,recipient_id=owner.id) for rule in rules]
    db.add_all(alerts);db.commit()
    path='/api/v1/incidents/'+incident['id']+'/links'
    linked=client.post(path,headers=auth,json={'indicator_id':ip.id,'alert_id':alerts[0].id})
    assert linked.status_code==201 and linked.json()['replayed'] is False
    assert client.post(path,headers=auth,json={'indicator_id':ip.id,'alert_id':alerts[0].id}).json()['replayed'] is True
    assert client.post(path,headers=auth,json={'indicator_id':ip.id,'alert_id':alerts[1].id}).status_code==409


def test_empty_selected_export_cannot_become_full_export(routes):
    client,db,people,feed,domain,ip=routes
    auth=people['administrator'][1]
    assert domain.value in client.get('/api/v1/export/csv',headers=auth).text
    response=client.get('/api/v1/export/csv?ids=',headers=auth)
    assert response.status_code==200 and len(response.text.splitlines())==1
    assert client.get('/api/v1/assignees',headers=people['executive'][1]).status_code==403
    users=client.get('/api/v1/assignees',headers=people['soc_analyst'][1]).json()['items']
    assert not any(u['role']=='executive' or 'email' in u for u in users)


def test_expiry_task_uses_persisted_deadline(routes,monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from app import tasks
    client,db,people,feed,domain,ip=routes
    monkeypatch.setattr(tasks,'Session',SimpleNamespace(begin=lambda:nullcontext(db)))
    tasks.expire.run()
    db.flush()
    assert domain.status=='expired' and ip.status=='active'
    assert db.scalars(select(Audit).where(Audit.action=='indicator.expired')).first()


def test_report_schedule_cancellation_and_owner_isolation(routes):
    from app.models import Report
    client,db,people,feed,domain,ip=routes
    analyst,auth=people['soc_analyst']
    report=Report(owner_id=analyst.id,title='CONTROLLED schedule',state='queued',schedule_hours=24,next_run=now())
    db.add(report);db.commit()
    path='/api/v1/reports/'+report.id
    assert client.patch(path,headers=people['threat_hunter'][1],json={'cancel':True}).status_code==403
    assert client.patch(path,headers=auth,json={'schedule_hours':None}).json()['next_run'] is None
    assert client.patch(path,headers=auth,json={'cancel':True}).json()['state']=='cancelled'
    assert client.patch(path,headers=auth,json={'cancel':True,'schedule_hours':24}).status_code==422


def test_report_schedule_creates_next_report(routes, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from app import tasks
    from app.models import Report
    client,db,people,feed,domain,ip=routes
    analyst,auth=people['soc_analyst']
    parent=Report(owner_id=analyst.id,title='CONTROLLED recurring',state='queued',schedule_hours=24,next_run=now()-timedelta(hours=1))
    db.add(parent);db.commit()
    monkeypatch.setattr(tasks,'Session',SimpleNamespace(begin=lambda:nullcontext(db)))
    monkeypatch.setattr(tasks,'capture_risk',lambda _db: None)
    monkeypatch.setattr(tasks,'recover_expired',lambda _db: None)
    tasks.schedule.run()
    db.flush()
    children=db.scalars(select(Report).where(Report.title==parent.title,Report.id!=parent.id)).all()
    assert len(children)==1
    child=children[0]
    assert child.owner_id==analyst.id and child.incident_id is None and child.state=='queued'
    assert db.scalars(select(Outbox).where(Outbox.topic=='report.generate',Outbox.object_id==child.id)).first()
    assert db.scalars(select(Audit).where(Audit.action=='report.scheduled',Audit.object_id==child.id)).first()
    db.refresh(parent)
    assert parent.next_run.replace(tzinfo=None)>now().replace(tzinfo=None)


def test_report_generation_rechecks_current_role_and_download_audience(routes):
    from app.models import Report
    from app.reporting import generate
    client,db,people,feed,domain,ip=routes
    engineer,auth=people['security_engineer']
    owner=people['administrator'][0]
    incident=Incident(title='CONTROLLED incident',owner_id=owner.id,creator_id=owner.id)
    db.add(incident);db.flush()
    report=Report(owner_id=engineer.id,title='CONTROLLED stale authorization',incident_id=incident.id)
    db.add(report);db.flush()
    with pytest.raises(ValueError,match='no longer has incident access'):generate(db,report)
    analyst,auth=people['soc_analyst']
    report=Report(owner_id=analyst.id,title='CONTROLLED prior technical',state='ready')
    db.add(report);db.commit()
    analyst.role='executive';db.commit()
    result=client.get('/api/v1/reports/'+report.id+'/download',headers=auth)
    assert result.status_code==403 and 'executive summary' in result.json()['message']


def test_report_blocks_red_incident_and_includes_public_provenance(routes,monkeypatch,tmp_path):
    from app import reporting
    from app.models import IncidentLink, Provenance, Report
    client,db,people,feed,domain,ip=routes
    owner=people['administrator'][0]
    incident=Incident(title='CONTROLLED mixed handling',owner_id=owner.id,creator_id=owner.id)
    db.add(incident);db.flush()
    domain.tlp='red'
    db.add_all([IncidentLink(incident_id=incident.id,indicator_id=domain.id),IncidentLink(incident_id=incident.id,indicator_id=ip.id),
        Timeline(incident_id=incident.id,kind='analyst_note',data={'text':'CONTROLLED restricted narrative'}),
        Provenance(indicator_id=ip.id,feed_id=feed.id,confidence=80,reference='CONTROLLED provenance')])
    report=Report(owner_id=owner.id,title='CONTROLLED report',incident_id=incident.id)
    db.add(report);db.commit()
    paragraphs=[]
    monkeypatch.setattr(reporting.settings(),'report_dir',str(tmp_path))
    class Document:
        def __init__(self,path):self.path=path
        def build(self,story):paragraphs.extend(item.getPlainText() for item in story if hasattr(item,'getPlainText'))
    monkeypatch.setattr(reporting,'SimpleDocTemplate',Document)
    with pytest.raises(reporting.ReportPolicyError,match='TLP:red'):
        reporting.generate(db,report)
    assert paragraphs==[]
    assert client.get('/api/v1/reports/'+report.id+'/download',headers=people['administrator'][1]).status_code==403
    public_report=Report(owner_id=owner.id,title='CONTROLLED permitted report')
    db.add(public_report);db.flush()
    evidence=reporting.generate(db,public_report)
    text='\n'.join(paragraphs)
    assert 'CONTROLLED restricted narrative' not in text
    assert domain.value not in text
    assert 'CONTROLLED provenance' in text and 'Score evidence' in text
    assert evidence['audience']=='operational'
