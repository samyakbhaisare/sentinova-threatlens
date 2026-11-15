"""Reference catalog, normalized mappings and append-only measured risk history."""
from alembic import op
import sqlalchemy as sa

from app.models import AttackTechnique, ReferenceSync, RiskSnapshot, TechniqueMapping

revision = '0003'
down_revision = '0002'


def upgrade():
    bind = op.get_bind()
    for model in (ReferenceSync, AttackTechnique, TechniqueMapping, RiskSnapshot):
        model.__table__.create(bind, checkfirst=True)
    if bind.dialect.name == 'postgresql':
        exists = bind.execute(sa.text("SELECT 1 FROM pg_trigger WHERE tgname='immutable_risk_snapshots' AND tgrelid='risk_snapshots'::regclass")).scalar()
        if not exists:
            op.execute('CREATE TRIGGER immutable_risk_snapshots BEFORE UPDATE OR DELETE OR TRUNCATE ON risk_snapshots FOR EACH STATEMENT EXECUTE FUNCTION reject_evidence_mutation()')
        op.execute('REVOKE UPDATE, DELETE, TRUNCATE ON risk_snapshots FROM threatlens')


def downgrade():
    raise RuntimeError('Historical risk and reference data are retained; downgrade is not supported')
