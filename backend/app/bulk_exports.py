"""Bounded, leased CSV/STIX generation. No ZIPs, uploads or external submissions."""
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

import stix2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, update

from .classification import allowed_labels
from .config import settings
from .db import Session, get_db
from .models import ExportItem, ExportJob, Indicator, Outbox, Provenance, TechniqueMapping, User, now, uid
from .reporting import csv_export, stix_export
from .security import audit, require

router = APIRouter(prefix='/api/v1/exports', tags=['Background exports'])
BATCH_SIZE = 500
MAX_BYTES = 512 * 1024 * 1024
MAX_ATTEMPTS = 3
LEASE_SECONDS = 600


class ExportSelection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    q: str = Field(default='', max_length=500)
    type: Literal['ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve'] | None = None
    status: Literal['active','expired','whitelisted','under_review'] | None = 'active'
    min_score: int = Field(default=0, ge=0, le=100)
    ids: list[str] | None = Field(default=None, max_length=10000)
    tag: str | None = Field(default=None, max_length=80)
    technique: str | None = Field(default=None, pattern=r'^T\d{4}(?:\.\d{3})?$')
    source_id: str | None = Field(default=None, max_length=36)


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    format: Literal['csv','stix']
    audience: Literal['public','internal'] = 'public'
    selection: ExportSelection = Field(default_factory=ExportSelection)
    max_records: int = Field(default=100000, ge=1, le=5000000)


class ExportStopped(Exception):
    """Cancellation, lost lease or classification/authorization change."""


def public_job(job):
    return {column.name:getattr(job,column.name) for column in job.__table__.columns if column.name not in ('attempt_token','artifact')}


def owned_job(db, identifier, user, lock=False):
    query=select(ExportJob).where(ExportJob.id==identifier).execution_options(populate_existing=True)
    if lock: query=query.with_for_update()
    job=db.scalar(query)
    if job is None: raise HTTPException(404,'Export job not found')
    if job.owner_id!=user.id and user.role!='administrator': raise HTTPException(403,'Export belongs to another user')
    return job


def artifact_path(job):
    token=str(UUID(job.attempt_token))
    identifier=str(UUID(job.id))
    extension='csv' if job.format=='csv' else 'json'
    expected=f'{identifier}-{token}.{extension}'
    if job.artifact is not None and job.artifact!=expected:
        raise ExportStopped('invalid_artifact_path')
    return Path(settings().report_dir)/'exports'/expected


def file_digest(path):
    checksum=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b''): checksum.update(chunk)
    return checksum.hexdigest()


def selection_query(job, labels, db):
    selection=ExportSelection.model_validate(job.filters)
    query=select(Indicator).where(Indicator.tlp.in_(labels),Indicator.score>=selection.min_score,Indicator.created_at<=job.created_at)
    if selection.type: query=query.where(Indicator.type==selection.type)
    if selection.status: query=query.where(Indicator.status==selection.status)
    if selection.q:
        query=query.where(Indicator.value.ilike('%'+selection.q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%',escape='\\'))
    if selection.ids is not None: query=query.where(Indicator.id.in_(selection.ids))
    if selection.source_id:
        query=query.where(select(Provenance.id).where(Provenance.indicator_id==Indicator.id,Provenance.feed_id==selection.source_id).exists())
    if selection.technique:
        query=query.where(select(TechniqueMapping.indicator_id).where(TechniqueMapping.indicator_id==Indicator.id,TechniqueMapping.technique_id==selection.technique).exists())
    if selection.tag:
        if db.get_bind().dialect.name=='sqlite':
            values=func.json_each(Indicator.tags).table_valued('value')
        else:
            values=func.json_array_elements_text(Indicator.tags).table_valued('value').render_derived()
        query=query.where(select(1).select_from(values).where(values.c.value==selection.tag).correlate(Indicator).exists())
    return query


def manifest_valid(db, job, labels):
    own=(ExportItem.job_id==job.id, ExportItem.attempt_token==job.attempt_token)
    invalid=db.scalar(select(func.count()).select_from(ExportItem).outerjoin(Indicator,Indicator.id==ExportItem.indicator_id).where(*own,
        or_(Indicator.id.is_(None),Indicator.tlp!=ExportItem.tlp,Indicator.tlp.not_in(labels))))
    count=db.scalar(select(func.count()).select_from(ExportItem).where(*own))
    return invalid==0 and count==job.record_count


def current_labels(db, job):
    user=db.get(User,job.owner_id,populate_existing=True)
    if user is None or not user.enabled: raise ExportStopped('owner_disabled')
    try: return allowed_labels(user.role,job.audience)
    except HTTPException as exc: raise ExportStopped('owner_permission_changed') from exc


def claim(db, identifier):
    token=uid()
    result=db.execute(update(ExportJob).where(ExportJob.id==identifier,ExportJob.state=='queued',ExportJob.attempts<MAX_ATTEMPTS).values(
        state='running',attempt_token=token,attempts=ExportJob.attempts+1,lease_until=now()+timedelta(seconds=LEASE_SECONDS),
        record_count=0,matching_count=0,artifact=None,checksum=None,error=None,completed_at=None))
    return token if result.rowcount==1 else None


def leased_job(db, identifier, token):
    job=db.scalar(select(ExportJob).where(ExportJob.id==identifier,ExportJob.attempt_token==token,ExportJob.state=='running',ExportJob.lease_until>now()).with_for_update())
    if job is None: raise ExportStopped('cancelled_or_lease_lost')
    return job


def generate_export(identifier, factory=Session):
    with factory.begin() as db:
        token=claim(db,identifier)
    if token is None: return False
    path=None
    try:
        with factory.begin() as db:
            job=leased_job(db,identifier,token)
            labels=current_labels(db,job)
            job.matching_count=db.scalar(select(func.count()).select_from(selection_query(job,labels,db).subquery()))
            job.limited=job.matching_count>job.max_records
            path=artifact_path(job)
            path.parent.mkdir(parents=True,exist_ok=True)
            format=job.format
        # Exclusive per-attempt path prevents a stale worker from replacing output.
        with path.open('x',encoding='utf-8',newline='') as handle:
            first_object=True
            if format=='stix':
                handle.write('{"type":"bundle","id":'+json.dumps('bundle--'+uid())+',"objects":[')
            else: handle.write(csv_export([]))
            last=''
            written=0
            while True:
                with factory.begin() as db:
                    job=leased_job(db,identifier,token)
                    labels=current_labels(db,job)
                    limit=min(BATCH_SIZE,job.max_records-written)
                    if limit<=0: break
                    rows=db.scalars(selection_query(job,labels,db).where(Indicator.id>last).order_by(Indicator.id).limit(limit).with_for_update(read=True)).all()
                    if not rows: break
                    for row in rows:
                        if format=='csv':
                            handle.write(csv_export([row]).partition('\r\n')[2])
                        else:
                            # Single-row serialization stays bounded. Repeated marking
                            # definitions are deduplicated by ID across the bundle.
                            for obj in stix_export([row])['objects']:
                                if obj['type']=='marking-definition': continue
                                if not first_object: handle.write(',')
                                handle.write(json.dumps(obj)); first_object=False
                        db.add(ExportItem(job_id=identifier,attempt_token=token,indicator_id=row.id,tlp=row.tlp,version=row.version))
                        written+=1
                    last=rows[-1].id
                    handle.flush()
                    if handle.tell()>MAX_BYTES: raise ExportStopped('artifact_byte_limit')
                    job.record_count=written
                    job.lease_until=now()+timedelta(seconds=LEASE_SECONDS)
            if format=='stix':
                for marking in (stix2.TLP_WHITE,stix2.TLP_GREEN,stix2.TLP_AMBER):
                    if not first_object: handle.write(',')
                    handle.write(marking.serialize()); first_object=False
                handle.write(']}')
        checksum=file_digest(path)
        with factory.begin() as db:
            job=leased_job(db,identifier,token)
            labels=current_labels(db,job)
            if not manifest_valid(db,job,labels): raise ExportStopped('classification_changed_during_export')
            job.artifact=path.name;job.checksum=checksum;job.byte_count=path.stat().st_size
            job.state='ready';job.completed_at=now();job.lease_until=None
            audit(db,None,'export.generated',identifier,{'count':job.record_count,'sha256':checksum,'audience':job.audience,'limited':job.limited})
        return True
    except Exception as exc:
        with factory.begin() as db:
            job=db.scalar(select(ExportJob).where(ExportJob.id==identifier,ExportJob.attempt_token==token,ExportJob.state=='running').with_for_update())
            if job:
                job.state='failed';job.error=str(exc) if isinstance(exc,ExportStopped) else type(exc).__name__
                job.lease_until=None;job.completed_at=now()
                audit(db,None,'export.failed',identifier,{'reason':job.error})
        return False


def recover_expired(db):
    jobs=db.scalars(select(ExportJob).where(ExportJob.state=='running',ExportJob.lease_until<=now()).limit(100).with_for_update(skip_locked=True).execution_options(populate_existing=True)).all()
    for job in jobs:
        job.lease_until=None
        if job.attempts>=MAX_ATTEMPTS:
            job.state='failed';job.error='lease_retry_limit'
        else:
            job.state='queued'
            db.add(Outbox(topic='export.generate',object_id=job.id))
        audit(db,None,'export.lease_recovered',job.id,{'attempts':job.attempts,'state':job.state})
    # Redis/broker loss can leave a durable queued job without a task message.
    # Re-dispatch is safe because claim() is atomic and duplicate tasks cannot own it.
    queued=db.scalars(select(ExportJob).where(ExportJob.state=='queued',ExportJob.id.not_in([job.id for job in jobs]),ExportJob.created_at<=now()-timedelta(seconds=LEASE_SECONDS),
        or_(ExportJob.lease_until.is_(None),ExportJob.lease_until<=now())).limit(100).with_for_update(skip_locked=True)).all()
    for job in queued:
        job.lease_until=now()+timedelta(seconds=LEASE_SECONDS)
        db.add(Outbox(topic='export.generate',object_id=job.id))
        audit(db,None,'export.queue_recovered',job.id)
    return len(jobs)+len(queued)


@router.post('',status_code=202)
def request_export(body:ExportRequest,request:Request,user=Depends(require('export')),db=Depends(get_db)):
    allowed_labels(user.role,body.audience)
    db.scalar(select(User).where(User.id==user.id).with_for_update())
    pending=db.scalar(select(func.count()).select_from(ExportJob).where(ExportJob.owner_id==user.id,ExportJob.state.in_(['queued','running'])))
    if pending>=5: raise HTTPException(429,'At most five active exports per user')
    job=ExportJob(owner_id=user.id,format=body.format,audience=body.audience,filters=body.selection.model_dump(),max_records=body.max_records)
    db.add(job);db.flush()
    db.add(Outbox(topic='export.generate',object_id=job.id))
    audit(db,user.id,'export.requested',job.id,{'format':job.format,'audience':job.audience},request.state.correlation_id)
    return public_job(job)


@router.get('')
def list_exports(user=Depends(require('export')),db=Depends(get_db)):
    return {'items':[public_job(job) for job in db.scalars(select(ExportJob).where(ExportJob.owner_id==user.id).order_by(ExportJob.created_at.desc()).limit(100))]}


@router.get('/{identifier}')
def get_export(identifier:str,user=Depends(require('export')),db=Depends(get_db)):
    return public_job(owned_job(db,identifier,user))


@router.post('/{identifier}/cancel')
def cancel_export(identifier:str,request:Request,user=Depends(require('export')),db=Depends(get_db)):
    job=owned_job(db,identifier,user,True)
    job.state='cancelled';job.lease_until=None
    audit(db,user.id,'export.cancelled',identifier,correlation_id=request.state.correlation_id)
    return public_job(job)


@router.post('/{identifier}/retry',status_code=202)
def retry_export(identifier:str,request:Request,user=Depends(require('export')),db=Depends(get_db)):
    job=owned_job(db,identifier,user,True)
    if job.state!='failed' or job.attempts>=MAX_ATTEMPTS: raise HTTPException(409,'Export cannot be retried')
    job.state='queued';job.error=None;job.artifact=None;job.checksum=None
    db.add(Outbox(topic='export.generate',object_id=identifier))
    audit(db,user.id,'export.retry_requested',identifier,correlation_id=request.state.correlation_id)
    return public_job(job)


@router.get('/{identifier}/download')
def download_export(identifier:str,request:Request,user=Depends(require('export')),db=Depends(get_db)):
    job=owned_job(db,identifier,user,True)
    if job.state!='ready': raise HTTPException(409,'Export is not ready')
    authenticated_version=user.token_version
    actor=db.scalar(select(User).where(User.id==user.id).with_for_update(read=True).execution_options(populate_existing=True))
    if actor is None or not actor.enabled or actor.token_version!=authenticated_version: raise HTTPException(401,'Session changed during authorization')
    labels=allowed_labels(actor.role,job.audience)
    # Hold source row share locks in the request transaction through FileResponse.
    # PostgreSQL concurrency/lifetime behavior is a separate integration gate.
    rows=db.execute(select(Indicator.id,Indicator.tlp,ExportItem.tlp).join(ExportItem,ExportItem.indicator_id==Indicator.id).where(
        ExportItem.job_id==job.id,ExportItem.attempt_token==job.attempt_token).with_for_update(read=True,of=Indicator).execution_options(yield_per=BATCH_SIZE))
    count=0
    try:
        for identifier_value,current,stored in rows:
            count+=1
            if current!=stored or current not in labels: raise HTTPException(403,'Source classification changed; request a new export')
    finally:
        rows.close()
    if count!=job.record_count: raise HTTPException(403,'Export manifest is incomplete')
    path=artifact_path(job)
    if not path.is_file() or file_digest(path)!=job.checksum: raise HTTPException(409,'Export artifact integrity check failed')
    audit(db,user.id,'export.downloaded',identifier,{'sha256':job.checksum},request.state.correlation_id)
    return FileResponse(path,media_type='text/csv' if job.format=='csv' else 'application/stix+json',filename=f'threatlens-{job.id}.'+('csv' if job.format=='csv' else 'json'))
