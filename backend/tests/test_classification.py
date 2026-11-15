"""Classified narrative, optimistic writes and sharing boundaries; SQLite is a test double."""
from contextlib import contextmanager
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from app import enrichment
from app.classification import allowed_labels, highest, incident_label
from app.models import Base, Incident, Indicator, Report, Timeline, now
from test_operations_routes import routes  # noqa: F401


def test_notes_raise_classification_and_stale_editor_is_rejected(routes):
    client, db, people, feed, domain, ip = routes
    auth = people['administrator'][1]
    path = '/api/v1/indicators/' + domain.id
    version = client.get(path, headers=auth).json()['version']
    changed = client.patch(path, headers=auth, json={'notes':'Controlled internal narrative','notes_tlp':'red','expected_version':version})
    assert changed.status_code == 200 and changed.json()['tlp'] == 'red'
    assert changed.json()['version'] > version
    assert client.patch(path, headers=auth, json={'notes':'stale overwrite','expected_version':version}).status_code == 409
    assert client.patch(path, headers=auth, json={'tlp':'clear'}).status_code == 409
    assert domain.value not in client.get('/api/v1/export/csv?audience=internal', headers=auth).text


def test_red_incident_note_revokes_report_without_red_ioc(routes):
    client, db, people, feed, domain, ip = routes
    owner, auth = people['soc_analyst']
    incident = client.post('/api/v1/incidents', headers=auth, json={'title':'CONTROLLED incident','indicator_id':ip.id}).json()
    response = client.post('/api/v1/incidents/'+incident['id']+'/timeline', headers=auth, json={'text':'CONTROLLED restricted free text','tlp':'red'})
    assert response.status_code == 201
    current = db.get(Incident, incident['id'])
    assert incident_label(db, current) == 'red'
    report = Report(owner_id=owner.id, title='CONTROLLED report', incident_id=current.id)
    db.add(report); db.commit()
    assert client.get('/api/v1/reports/'+report.id+'/download', headers=auth).status_code == 403


@pytest.mark.parametrize('label',['green','amber','red'])
def test_external_enrichment_never_receives_restricted_value(routes, monkeypatch, label):
    client, db, people, feed, domain, ip = routes
    ip.tlp = label
    monkeypatch.setattr(enrichment, 'provider_request', lambda *a, **k: pytest.fail('Restricted IOC sent outside organization'))
    result = enrichment.enrich(db, ip)
    assert result[0]['status'] == 'blocked'


def test_orm_optimistic_version_prevents_lost_update():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as db:
        row = Indicator(type='domain', value='controlled.example.org', expires_at=now())
        db.add(row); db.flush(); identifier = row.id
    with factory() as first, factory() as second:
        a, b = first.get(Indicator, identifier), second.get(Indicator, identifier)
        a.tlp = 'red'; first.commit()
        b.tlp = 'green'
        with pytest.raises(StaleDataError): second.commit()
    with factory() as db:
        assert db.get(Indicator, identifier).tlp == 'red'


def test_tlp_role_audience_matrix():
    from fastapi import HTTPException
    assert highest('amber','red','green') == 'red'
    for role in ('administrator','security_engineer','incident_responder','threat_hunter','soc_analyst'):
        assert allowed_labels(role,'public') == ['clear']
        assert 'red' not in allowed_labels(role,'internal')
    assert allowed_labels('soc_analyst','internal') == ['clear']
    with pytest.raises(HTTPException): allowed_labels('executive','internal')


def test_analyst_tags_are_internal_by_default(routes):
    client, db, people, feed, domain, ip = routes
    result=client.patch('/api/v1/indicators/'+ip.id,headers=people['soc_analyst'][1],json={'tags':['CONTROLLED internal asset label']})
    assert result.status_code==200 and result.json()['tlp']=='amber'
    assert ip.value not in client.get('/api/v1/export/csv',headers=people['soc_analyst'][1]).text


def test_legacy_event_replay_preserves_stricter_classification(routes):
    from app.models import SecurityEvent
    client, db, people, feed, domain, ip = routes
    stamp=now()
    event=SecurityEvent(source='controlled',external_id='legacy',occurred_at=stamp,asset='controlled-host',observables=[{'type':'ip','value':ip.value}],details={},controlled_test=True,tlp='red',digest='legacy-schema-digest')
    db.add(event);db.commit()
    payload={'source':event.source,'external_id':event.external_id,'occurred_at':stamp.isoformat(),'asset':event.asset,'observables':event.observables,'controlled_test':True}
    response=client.post('/api/v1/events',headers=people['administrator'][1],json=payload)
    assert response.status_code==201 and response.json()['replayed'] is True
    assert db.get(SecurityEvent,event.id).tlp=='red'
    assert client.post('/api/v1/events',headers=people['administrator'][1],json={**payload,'tlp':'clear'}).status_code==409


def test_generic_pdf_manifest_revokes_download_after_source_reclassification(routes,monkeypatch,tmp_path):
    from app import reporting
    from app.security import audit
    client,db,people,feed,domain,ip=routes
    owner,auth=people['administrator']
    monkeypatch.setattr(reporting.settings(),'report_dir',str(tmp_path))
    report=Report(owner_id=owner.id,title='CONTROLLED manifest report')
    db.add(report);db.flush()
    proof=reporting.generate(db,report)
    audit(db,None,'report.generated',report.id,proof)
    db.commit()
    response=client.get('/api/v1/reports/'+report.id+'/download',headers=auth)
    assert response.status_code==200 and response.content.startswith(b'%PDF')
    ip.tlp='green';db.commit()
    assert client.get('/api/v1/reports/'+report.id+'/download',headers=auth).status_code==403


def test_classification_migration_adds_columns_preserving_legacy_evidence():
    path = Path(__file__).parents[1]/'migrations/versions/0002_classification_versions.py'
    spec = spec_from_file_location('classification_migration', path)
    migration = module_from_spec(spec); spec.loader.exec_module(migration)
    engine = create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE indicators(id TEXT PRIMARY KEY, tlp TEXT, notes TEXT)")
        connection.exec_driver_sql("INSERT INTO indicators VALUES ('old','clear','CONTROLLED unclassified note')")
        connection.exec_driver_sql('CREATE TABLE indicator_sources(id TEXT, indicator_id TEXT)')
        connection.exec_driver_sql("INSERT INTO indicator_sources VALUES ('source','old')")
        for table in ('security_events','incidents','incident_timeline','reports','alerts','alert_rules'):
            connection.exec_driver_sql(f'CREATE TABLE {table}(id TEXT PRIMARY KEY)')
            connection.exec_driver_sql(f"INSERT INTO {table} VALUES ('old')")
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert connection.exec_driver_sql('SELECT notes_tlp,tlp,notes FROM indicators').one() == ('red','red','CONTROLLED unclassified note')
        assert connection.exec_driver_sql('SELECT tlp FROM incident_timeline').scalar() == 'red'
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
        assert connection.exec_driver_sql('SELECT count(*) FROM incident_timeline').scalar() == 1
