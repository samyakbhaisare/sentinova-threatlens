"""Durable leased exports and current-classification manifests."""
from alembic import op

from app.models import ExportItem, ExportJob, ReportItem

revision = '0004'
down_revision = '0003'


def upgrade():
    ExportJob.__table__.create(op.get_bind(), checkfirst=True)
    ExportItem.__table__.create(op.get_bind(), checkfirst=True)
    ReportItem.__table__.create(op.get_bind(), checkfirst=True)


def downgrade():
    raise RuntimeError('Export history is retained; destructive downgrade is not supported')
