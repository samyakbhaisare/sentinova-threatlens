from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from .db import engine

command.upgrade(Config('alembic.ini'), 'head')
with engine.begin() as db:
    db.execute(text(Path('grants.sql').read_text()))
