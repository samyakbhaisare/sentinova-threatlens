"""Initial ThreatLens schema, append-only evidence guards."""
from alembic import op
from app.db import Base
from app import models  # noqa: F401

revision = '0001'
down_revision = None


def upgrade():
    Base.metadata.create_all(op.get_bind())
    op.execute("""CREATE FUNCTION reject_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'Evidence is append-only'; END; $$""")
    for table in ('audit_log', 'incident_timeline'):
        op.execute(f'CREATE TRIGGER immutable_evidence BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_evidence_mutation()')


def downgrade():
    raise RuntimeError('Destructive downgrade requires an explicit reviewed recovery procedure')
