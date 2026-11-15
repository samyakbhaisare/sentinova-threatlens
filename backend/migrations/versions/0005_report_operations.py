"""Durable, leased report generation with attempt and artifact evidence."""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'


def upgrade():
    bind = op.get_bind()
    existing = {column['name'] for column in sa.inspect(bind).get_columns('reports')}
    additions = [
        ('attempts', sa.Column('attempts', sa.Integer, nullable=False, server_default='0')),
        ('lease_until', sa.Column('lease_until', sa.DateTime(timezone=True), nullable=True)),
        ('checksum', sa.Column('checksum', sa.String(64), nullable=True)),
        ('artifact_bytes', sa.Column('artifact_bytes', sa.Integer, nullable=True)),
        ('ready_at', sa.Column('ready_at', sa.DateTime(timezone=True), nullable=True)),
    ]
    for name, column in additions:
        if name not in existing:
            op.add_column('reports', column)
    # Existing completed reports keep their state; evidence is recorded on the next generation.
    if 'ready_at' not in existing:
        op.execute("UPDATE reports SET ready_at = created_at WHERE state = 'ready'")


def downgrade():
    raise RuntimeError('Report generation evidence is retained; destructive downgrade is not supported')
