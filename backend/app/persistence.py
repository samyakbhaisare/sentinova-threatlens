"""Portable conflict-safe inserts; production uses PostgreSQL, SQLite is test-only."""
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert


def insert_for(db, model):
    return (sqlite_insert if db.get_bind().dialect.name == 'sqlite' else pg_insert)(model)
