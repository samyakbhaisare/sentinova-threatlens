"""Real PostgreSQL gates. Never start containers; run only with an isolated test DB."""
import os
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, delete, select, text, update
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import sessionmaker

from app.models import Indicator, RiskSnapshot, now
from app.risk import capture

pytestmark = pytest.mark.integration


def test_postgres_share_lock_blocks_concurrent_classification_write():
    url=os.environ.get('TEST_DATABASE_URL')
    if not url: pytest.skip('Isolated PostgreSQL URL required; Docker is not started by this test')
    if not url.rsplit('/',1)[-1].startswith('threatlens_test'):
        raise RuntimeError('A dedicated threatlens_test database is required')
    engine=create_engine(url)
    factory=sessionmaker(engine,expire_on_commit=False)
    identifier=None
    try:
        with factory.begin() as db:
            row=Indicator(type='domain',value='controlled-lock-'+str(now().timestamp())+'.example.org',expires_at=now()+timedelta(days=1))
            db.add(row);db.flush();identifier=row.id
        with factory() as reader:
            reader.execute(select(Indicator).where(Indicator.id==identifier).with_for_update(read=True)).all()
            with factory() as writer:
                writer.execute(text("SET LOCAL lock_timeout = '200ms'"))
                with pytest.raises(OperationalError) as failure:
                    writer.execute(update(Indicator).where(Indicator.id==identifier).values(tlp='red'))
                assert getattr(failure.value.orig,'sqlstate',None)=='55P03'
                writer.rollback()
            reader.rollback()
    finally:
        if identifier:
            with factory.begin() as db:
                db.execute(delete(Indicator).where(Indicator.id==identifier))  # Only this test's unique fixture.
        engine.dispose()


def test_postgres_snapshot_guard_rejects_mutation(db):
    snapshot=capture(db);db.flush()
    with pytest.raises(DBAPIError) as failure:
        with db.begin_nested():
            db.execute(update(RiskSnapshot).where(RiskSnapshot.id==snapshot.id).values(data={'forged':True}))
    assert getattr(failure.value.orig,'sqlstate',None) in ('42501','P0001')
