"""Unit-test emitted ingestion effects. SQL execution/locking remains a PostgreSQL gate."""
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.dml import Insert

from app.intelligence import canonical, ingest
from app.models import Audit, Indicator, Outbox, now


class IngestionSession:
    def __init__(self, existing=None):
        self.existing=existing;self.added=[];self.statements=[];self.row=None

    def scalar(self, statement):
        if not isinstance(statement, Insert):return 0
        self.statements.append(statement)
        values=statement.compile(dialect=postgresql.dialect()).params
        self.row=self.existing or Indicator(id=values['id'],type=values['type'],value=values['value'],reputation=values['reputation'],confidence=values['confidence'],last_seen=values['last_seen'])
        return self.row.id

    def execute(self, statement):self.statements.append(statement)
    def get(self, *args, **kwargs):return self.row
    def add(self, record):self.added.append(record)


def test_new_ioc_queues_enrichment_and_audit_with_source_provenance():
    db=IngestionSession()
    feed=SimpleNamespace(id='controlled-feed',url='https://example.org/feed',reliability=80,ttl_days=30)
    row=ingest(db,feed,{'type':'domain','value':'EXAMPLE.ORG.','confidence':75,'tlp':'amber'})
    assert row.value=='example.org'
    provenance=db.statements[1].compile(dialect=postgresql.dialect()).params
    assert provenance['feed_id']==feed.id and provenance['indicator_id']==row.id
    assert any(isinstance(record,Outbox) and record.topic=='indicator.enrich' and record.object_id==row.id for record in db.added)
    evidence=next(record for record in db.added if isinstance(record,Audit))
    assert evidence.action=='indicator.ingested' and evidence.data['data']['tlp']=='amber'
    assert evidence.data['data']['created'] is True


def test_replay_keeps_original_identity_and_does_not_requeue_new_record_enrichment():
    existing=Indicator(id='existing-controlled',type='domain',value='example.org',reputation=80,confidence=75,last_seen=now())
    db=IngestionSession(existing)
    feed=SimpleNamespace(id='controlled-feed',url='https://example.org/feed',reliability=80,ttl_days=30)
    assert ingest(db,feed,{'type':'domain','value':'example.org'}).id==existing.id
    assert not any(isinstance(record,Outbox) and record.topic=='indicator.enrich' for record in db.added)
    assert any(isinstance(record,Audit) and not record.data['data']['created'] for record in db.added)


def test_invalid_records_have_no_persistence_or_queue_effects():
    db=IngestionSession()
    with pytest.raises(ValueError):ingest(db,SimpleNamespace(),{'type':'domain','value':42})
    assert not db.statements and not db.added
    with pytest.raises(ValueError):canonical('url','https://example.org/'+'界'*1000)
