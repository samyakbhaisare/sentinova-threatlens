from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now():
    return datetime.now(timezone.utc)


def uid():
    return str(uuid4())


class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Record, Base):
    __tablename__ = 'users'
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    mfa_secret: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_step: Mapped[int] = mapped_column(Integer, default=0)
    layout: Mapped[list] = mapped_column(JSON, default=lambda: ['metrics', 'trends', 'map'])


class Refresh(Record, Base):
    __tablename__ = 'refresh_tokens'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    family: Mapped[str] = mapped_column(String(36), index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Reset(Record, Base):
    __tablename__ = 'password_resets'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class Feed(Record, Base):
    __tablename__ = 'feeds'
    name: Mapped[str] = mapped_column(String(120), unique=True)
    adapter: Mapped[str] = mapped_column(String(32))
    url: Mapped[str] = mapped_column(Text)
    secret_ref: Mapped[str] = mapped_column(String(100), default='')
    interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    ttl_days: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_poll: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    ingested: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    reliability: Mapped[int] = mapped_column(Integer, default=50)


class Indicator(Record, Base):
    __tablename__ = 'indicators'
    __table_args__ = (UniqueConstraint('type', 'value'), CheckConstraint('score BETWEEN 0 AND 100'), Index('ix_active_score', 'status', 'score'))
    type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(2048))
    score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    reputation: Mapped[int] = mapped_column(Integer, default=0)
    breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    tlp: Mapped[str] = mapped_column(String(10), default='clear')
    notes_tlp: Mapped[str] = mapped_column(String(10), default='amber', server_default='amber')
    version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    status: Mapped[str] = mapped_column(String(20), default='active')
    category: Mapped[str] = mapped_column(String(100), default='unknown')
    tags: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default='')
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    __mapper_args__ = {'version_id_col': version}


class Provenance(Record, Base):
    __tablename__ = 'indicator_sources'
    __table_args__ = (UniqueConstraint('indicator_id', 'feed_id'),)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey('feeds.id'))
    confidence: Mapped[int] = mapped_column(Integer)
    tlp: Mapped[str] = mapped_column(String(10), default='clear', server_default='clear')
    reference: Mapped[str] = mapped_column(Text, default='')
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Enrichment(Record, Base):
    __tablename__ = 'enrichments'
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Relationship(Record, Base):
    __tablename__ = 'indicator_relationships'
    __table_args__ = (UniqueConstraint('source_id', 'target_id', 'kind'), CheckConstraint('source_id != target_id'))
    source_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    kind: Mapped[str] = mapped_column(String(40))


class SecurityEvent(Record, Base):
    __tablename__ = 'security_events'
    __table_args__ = (UniqueConstraint('source', 'external_id'),)
    source: Mapped[str] = mapped_column(String(100))
    external_id: Mapped[str] = mapped_column(String(200))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    asset: Mapped[str] = mapped_column(String(200))
    observables: Mapped[list] = mapped_column(JSON)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    digest: Mapped[str] = mapped_column(String(64))
    controlled_test: Mapped[bool] = mapped_column(Boolean, default=False)
    tlp: Mapped[str] = mapped_column(String(10), default='amber', server_default='amber')


class Sighting(Record, Base):
    __tablename__ = 'sightings'
    __table_args__ = (UniqueConstraint('indicator_id', 'event_id'),)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey('security_events.id'), index=True)


class EventObservable(Record, Base):
    __tablename__ = 'event_observables'
    __table_args__ = (UniqueConstraint('event_id', 'type', 'value'), Index('ix_observable_lookup', 'type', 'value'))
    event_id: Mapped[str] = mapped_column(ForeignKey('security_events.id'), index=True)
    type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(2048))


class AlertRule(Record, Base):
    __tablename__ = 'alert_rules'
    name: Mapped[str] = mapped_column(String(150))
    min_score: Mapped[int] = mapped_column(Integer, default=70)
    min_sightings: Mapped[int] = mapped_column(Integer, default=1)
    category: Mapped[str | None] = mapped_column(String(100))
    feed_id: Mapped[str | None] = mapped_column(ForeignKey('feeds.id'))
    recipient_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    __mapper_args__ = {'version_id_col': version}


class Alert(Record, Base):
    __tablename__ = 'alerts'
    __table_args__ = (UniqueConstraint('indicator_id', 'rule_id'),)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'))
    rule_id: Mapped[str] = mapped_column(ForeignKey('alert_rules.id'))
    score: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default='new')
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    recipient_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    __mapper_args__ = {'version_id_col': version}


class Incident(Record, Base):
    __tablename__ = 'incidents'
    title: Mapped[str] = mapped_column(String(200))
    state: Mapped[str] = mapped_column(String(20), default='open')
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    creator_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    checklist: Mapped[dict] = mapped_column(JSON, default=dict)
    tlp: Mapped[str] = mapped_column(String(10), default='amber', server_default='amber')
    version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    __mapper_args__ = {'version_id_col': version}


class IncidentLink(Record, Base):
    __tablename__ = 'incident_links'
    __table_args__ = (UniqueConstraint('incident_id', 'indicator_id'),)
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.id'), index=True)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), index=True)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey('alerts.id'))


class Timeline(Record, Base):
    __tablename__ = 'incident_timeline'
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.id'), index=True)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    kind: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)
    tlp: Mapped[str] = mapped_column(String(10), default='amber', server_default='amber')


class Audit(Record, Base):
    __tablename__ = 'audit_log'
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_id: Mapped[str | None] = mapped_column(String(100))
    correlation_id: Mapped[str] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON)
    digest: Mapped[str] = mapped_column(String(64))


class Outbox(Record, Base):
    __tablename__ = 'outbox'
    topic: Mapped[str] = mapped_column(String(100))
    object_id: Mapped[str] = mapped_column(String(36))
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class Hunt(Record, Base):
    __tablename__ = 'hunts'
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    name: Mapped[str] = mapped_column(String(150))
    query: Mapped[dict] = mapped_column(JSON)


class Report(Record, Base):
    __tablename__ = 'reports'
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    title: Mapped[str] = mapped_column(String(200))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey('incidents.id'))
    state: Mapped[str] = mapped_column(String(20), default='queued')
    error: Mapped[str | None] = mapped_column(Text)
    schedule_hours: Mapped[int | None] = mapped_column(Integer)
    next_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tlp: Mapped[str] = mapped_column(String(10), default='amber', server_default='amber')
    version: Mapped[int] = mapped_column(Integer, default=1, server_default='1')
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default='0')
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checksum: Mapped[str | None] = mapped_column(String(64))
    artifact_bytes: Mapped[int | None] = mapped_column(Integer)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __mapper_args__ = {'version_id_col': version}


class Notification(Record, Base):
    __tablename__ = 'notifications'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey('alerts.id'))
    read: Mapped[bool] = mapped_column(Boolean, default=False)


class ReferenceSync(Record, Base):
    __tablename__ = 'reference_syncs'
    state: Mapped[str] = mapped_column(String(20), default='queued')
    source_url: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str | None] = mapped_column(String(64))
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(100))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttackTechnique(Base):
    __tablename__ = 'attack_techniques'
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    stix_id: Mapped[str | None] = mapped_column(String(100), unique=True)
    name: Mapped[str | None] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default='')
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    known: Mapped[bool] = mapped_column(Boolean, default=False)
    catalog_present: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_url: Mapped[str | None] = mapped_column(Text)


class TechniqueMapping(Base):
    __tablename__ = 'indicator_attack_techniques'
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), primary_key=True)
    technique_id: Mapped[str] = mapped_column(ForeignKey('attack_techniques.technique_id'), primary_key=True, index=True)


class RiskSnapshot(Record, Base):
    __tablename__ = 'risk_snapshots'
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), unique=True, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict] = mapped_column(JSON)


class ExportJob(Record, Base):
    __tablename__ = 'export_jobs'
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    format: Mapped[str] = mapped_column(String(10))
    audience: Mapped[str] = mapped_column(String(16))
    filters: Mapped[dict] = mapped_column(JSON, default=dict)
    max_records: Mapped[int] = mapped_column(Integer, default=100000)
    state: Mapped[str] = mapped_column(String(20), default='queued', index=True)
    attempt_token: Mapped[str | None] = mapped_column(String(36))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    matching_count: Mapped[int] = mapped_column(Integer, default=0)
    limited: Mapped[bool] = mapped_column(Boolean, default=False)
    artifact: Mapped[str | None] = mapped_column(String(100))
    checksum: Mapped[str | None] = mapped_column(String(64))
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(100))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExportItem(Base):
    __tablename__ = 'export_items'
    job_id: Mapped[str] = mapped_column(ForeignKey('export_jobs.id'), primary_key=True)
    attempt_token: Mapped[str] = mapped_column(String(36), primary_key=True)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), primary_key=True, index=True)
    tlp: Mapped[str] = mapped_column(String(10))
    version: Mapped[int] = mapped_column(Integer)


class ReportItem(Base):
    __tablename__ = 'report_items'
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'), primary_key=True)
    indicator_id: Mapped[str] = mapped_column(ForeignKey('indicators.id'), primary_key=True, index=True)
    tlp: Mapped[str] = mapped_column(String(10))
    version: Mapped[int] = mapped_column(Integer)
