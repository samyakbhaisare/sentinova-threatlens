GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO threatlens;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log, incident_timeline FROM threatlens;
REVOKE ALL ON alembic_version FROM threatlens;
REVOKE UPDATE, DELETE, TRUNCATE ON risk_snapshots FROM threatlens;
