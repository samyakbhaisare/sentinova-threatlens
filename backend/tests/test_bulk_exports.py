"""Real file generation and SQLite job contracts; PostgreSQL/Redis remain separate gates."""
import csv
import json
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
import stix2
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import bulk_exports as exports
from app.config import settings
from app.db import Base, get_db
from app.main import app
from app.models import ExportItem, ExportJob, Indicator, User, now
from app.security import issue


@pytest.fixture
def store(tmp_path,monkeypatch):
    engine=create_engine('sqlite:///'+(tmp_path/'controlled.db').as_posix(),connect_args={'check_same_thread':False,'timeout':10})
    Base.metadata.create_all(engine)
    factory=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(settings(),'report_dir',str(tmp_path/'reports'))
    with factory.begin() as db:
        user=User(name='CONTROLLED exporter',email='exporter@example.org',role='threat_hunter',password_hash='not-used-for-login')
        db.add(user);db.flush();owner=user.id
        db.add_all([Indicator(type='domain',value=f'controlled-{i}.example.org',tlp='clear',score=i%101,expires_at=now()+timedelta(days=7)) for i in range(1205)])
    yield factory,owner
    engine.dispose()


def new_job(factory,owner,format='csv',**kwargs):
    with factory.begin() as db:
        job=ExportJob(owner_id=owner,format=format,audience=kwargs.pop('audience','public'),filters=kwargs.pop('filters',{}),**kwargs)
        db.add(job);db.flush();return job.id


def test_csv_streams_beyond_legacy_limit_and_manifest_is_complete(store):
    factory,owner=store
    identifier=new_job(factory,owner)
    assert exports.generate_export(identifier,factory)
    with factory() as db:
        job=db.get(ExportJob,identifier)
        assert job.state=='ready' and job.record_count==1205 and not job.limited
        with exports.artifact_path(job).open(newline='',encoding='utf-8') as handle:
            rows=list(csv.reader(handle))
        assert len(rows)==1206
        assert db.scalar(select(func.count()).select_from(ExportItem).where(ExportItem.job_id==identifier))==1205
        assert exports.manifest_valid(db,job,['clear'])
        checksum=job.checksum
    assert not exports.generate_export(identifier,factory)
    with factory() as db: assert db.get(ExportJob,identifier).checksum==checksum


def test_stix_bundle_is_valid_and_record_limit_is_explicit(store):
    factory,owner=store
    identifier=new_job(factory,owner,'stix',max_records=12)
    assert exports.generate_export(identifier,factory)
    with factory() as db:
        job=db.get(ExportJob,identifier)
        assert job.limited and job.matching_count==1205 and job.record_count==12
        parsed=stix2.parse(exports.artifact_path(job).read_text())
        assert parsed.type=='bundle'
        assert len([obj for obj in parsed.objects if obj.type=='indicator'])==12
        assert len({obj.id for obj in parsed.objects})==len(parsed.objects)


def test_reclassification_invalidates_even_an_internal_artifact(store):
    factory,owner=store
    identifier=new_job(factory,owner,audience='internal',max_records=3)
    assert exports.generate_export(identifier,factory)
    with factory.begin() as db:
        item=db.scalars(select(ExportItem).where(ExportItem.job_id==identifier)).first()
        db.get(Indicator,item.indicator_id).tlp='amber'
    with factory() as db:
        job=db.get(ExportJob,identifier)
        assert not exports.manifest_valid(db,job,['clear','green','amber'])


def test_tag_selection_is_exact_not_a_substring_match(store):
    factory,owner=store
    with factory.begin() as db:
        rows=db.scalars(select(Indicator).order_by(Indicator.id).limit(2)).all()
        rows[0].tags=['CONTROLLED tag'];rows[1].tags=['CONTROLLED tag suffix']
    identifier=new_job(factory,owner,filters={'tag':'CONTROLLED tag'})
    assert exports.generate_export(identifier,factory)
    with factory() as db:
        job=db.get(ExportJob,identifier)
        assert job.record_count==1 and job.matching_count==1


def test_two_workers_cannot_claim_one_job(store):
    factory,owner=store
    identifier=new_job(factory,owner)
    barrier=Barrier(2)
    def worker():
        barrier.wait()
        with factory.begin() as db: return exports.claim(db,identifier)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results=list(workers.map(lambda _:worker(),range(2)))
    assert sum(result is not None for result in results)==1


def test_expired_lease_is_replayed_with_new_attempt_without_overwrite(store):
    factory,owner=store
    identifier=new_job(factory,owner,max_records=2)
    with factory.begin() as db:
        old_token=exports.claim(db,identifier)
        job=db.get(ExportJob,identifier);job.lease_until=now()-timedelta(seconds=1)
    with factory.begin() as db: assert exports.recover_expired(db)==1
    assert exports.generate_export(identifier,factory)
    with factory() as db:
        job=db.get(ExportJob,identifier)
        assert job.attempt_token!=old_token and job.attempts==2


def test_old_queued_job_is_redispatched_after_broker_loss(store):
    from app.models import Outbox
    factory,owner=store
    identifier=new_job(factory,owner,max_records=2)
    with factory.begin() as db:
        db.get(ExportJob,identifier).created_at=now()-timedelta(minutes=20)
    with factory.begin() as db: assert exports.recover_expired(db)==1
    with factory.begin() as db: assert exports.recover_expired(db)==0
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(Outbox).where(Outbox.topic=='export.generate',Outbox.object_id==identifier))==1


def test_cancelled_and_disabled_owner_jobs_cannot_publish(store):
    factory,owner=store
    cancelled=new_job(factory,owner)
    with factory.begin() as db: db.get(ExportJob,cancelled).state='cancelled'
    assert not exports.generate_export(cancelled,factory)
    disabled=new_job(factory,owner)
    with factory.begin() as db: db.get(User,owner).enabled=False
    assert not exports.generate_export(disabled,factory)
    with factory() as db:
        job=db.get(ExportJob,disabled)
        assert job.state=='failed' and job.artifact is None and job.error=='owner_disabled'


def test_artifact_failure_can_be_retried_without_replacing_first_attempt(store,monkeypatch):
    factory,owner=store
    identifier=new_job(factory,owner,max_records=2)
    original=exports.file_digest
    def fail(path): raise OSError('controlled storage failure')
    monkeypatch.setattr(exports,'file_digest',fail)
    assert not exports.generate_export(identifier,factory)
    with factory.begin() as db:
        job=db.get(ExportJob,identifier)
        first_path=exports.artifact_path(job)
        original_bytes=first_path.read_bytes()
        assert job.state=='failed' and job.artifact is None
        job.state='queued'
    monkeypatch.setattr(exports,'file_digest',original)
    assert exports.generate_export(identifier,factory)
    with factory() as db: assert exports.artifact_path(db.get(ExportJob,identifier))!=first_path
    assert first_path.read_bytes()==original_bytes


def test_export_api_ownership_empty_selection_and_integrity(store):
    factory,owner=store
    with factory.begin() as db:
        token,_=issue(db,db.get(User,owner))
        other=User(name='CONTROLLED other',email='other@example.org',role='soc_analyst',password_hash='unused')
        db.add(other);db.flush();other_token,_=issue(db,other)
    def dependency():
        with factory() as db:
            try: yield db;db.commit()
            except Exception: db.rollback();raise
    app.dependency_overrides[get_db]=dependency
    try:
        with TestClient(app) as client:
            auth={'Authorization':'Bearer '+token};other_auth={'Authorization':'Bearer '+other_token}
            result=client.post('/api/v1/exports',headers=auth,json={'format':'csv','selection':{'ids':[]}})
            assert result.status_code==202
            identifier=result.json()['id']
            assert client.get('/api/v1/exports/'+identifier,headers=other_auth).status_code==403
            assert client.post('/api/v1/exports/'+identifier+'/cancel',headers=other_auth).status_code==403
            assert exports.generate_export(identifier,factory)
            response=client.get('/api/v1/exports/'+identifier+'/download',headers=auth)
            assert response.status_code==200 and len(response.text.splitlines())==1
            with factory() as db:
                path=exports.artifact_path(db.get(ExportJob,identifier))
                path.write_text('controlled corruption')
            assert client.get('/api/v1/exports/'+identifier+'/download',headers=auth).status_code==409
    finally: app.dependency_overrides.clear()
