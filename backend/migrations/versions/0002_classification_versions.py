"""Add classified narrative and optimistic concurrency without deleting existing data."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'


def upgrade():
    bind = op.get_bind()
    additions = {
        'indicators': [('notes_tlp', sa.String(10), 'amber'), ('version', sa.Integer, '1')],
        'indicator_sources': [('tlp', sa.String(10), 'clear')],
        'security_events': [('tlp', sa.String(10), 'red')],
        'incidents': [('tlp', sa.String(10), 'amber'), ('version', sa.Integer, '1')],
        'incident_timeline': [('tlp', sa.String(10), 'red')],
        'reports': [('tlp', sa.String(10), 'amber'), ('version', sa.Integer, '1')],
        'alerts': [('version', sa.Integer, '1')],
        'alert_rules': [('version', sa.Integer, '1')],
    }
    added = set()
    for table, columns in additions.items():
        existing = {column['name'] for column in sa.inspect(bind).get_columns(table)}
        for name, kind, default in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, kind, nullable=False, server_default=default))
                added.add((table, name))
    # Baseline 0001 creates from current metadata on a fresh install; guards above
    # also support existing installations whose tables lack these new columns.
    if ('indicator_sources', 'tlp') in added:
        op.execute('UPDATE indicator_sources SET tlp = (SELECT tlp FROM indicators WHERE indicators.id = indicator_sources.indicator_id)')
    if ('indicators', 'notes_tlp') in added:
        columns = {column['name'] for column in sa.inspect(bind).get_columns('indicators')}
        predicates = ["notes <> ''"]
        for field in ('tags', 'techniques'):
            if field in columns:
                predicates.append(f"CAST({field} AS TEXT) NOT IN ('[]','null')")
        op.execute("UPDATE indicators SET notes_tlp='red', tlp='red' WHERE " + ' OR '.join(predicates))
    if ('incidents', 'tlp') in added:
        op.execute("UPDATE incidents SET tlp='red'")
    if ('reports', 'tlp') in added:
        op.execute("UPDATE reports SET tlp='red'")
    for table in ('incident_timeline', 'security_events'):
        if (table, 'tlp') in added and bind.dialect.name == 'postgresql':
            # ADD COLUMN classified legacy rows red without UPDATEing evidence;
            # future rows default amber. Evidence guards remain enabled.
            op.alter_column(table, 'tlp', server_default='amber')


def downgrade():
    raise RuntimeError('Destructive classification downgrade is not supported')
