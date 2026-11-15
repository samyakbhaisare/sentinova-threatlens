"""NFR-12: audit evidence older than a year survives and cannot be mutated."""
from datetime import timedelta

import pytest
from sqlalchemy import func, select, text

from app.models import Audit, now


def test_audit_rows_older_than_one_year_are_retained(db):
    stamp = now() - timedelta(days=400)
    row = Audit(actor_id=None, action='retention.controlled', object_id='controlled-retention',
                correlation_id='controlled-correlation', data={'controlled': True}, digest='controlled',
                created_at=stamp)
    db.add(row)
    db.flush()
    assert db.scalar(select(func.count()).select_from(Audit).where(Audit.id == row.id)) == 1
    assert db.scalar(select(func.count()).select_from(Audit).where(
        Audit.created_at < now() - timedelta(days=365))) >= 1


def test_audit_evidence_rejects_delete_and_update(db):
    row = Audit(actor_id=None, action='retention.immutable', object_id='controlled-immutable',
                correlation_id='controlled-correlation', data={}, digest='controlled')
    db.add(row)
    db.flush()
    for statement in ('DELETE FROM audit_log WHERE id = :id',
                      "UPDATE audit_log SET action = 'tampered' WHERE id = :id"):
        with pytest.raises(Exception):
            with db.begin_nested():
                db.execute(text(statement), {'id': row.id})
    db.rollback()
