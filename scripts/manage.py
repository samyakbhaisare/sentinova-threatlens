"""Local operator runner; uses generated .env without printing credentials."""
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))


def migrate(test=False):
    import psycopg
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    url = make_url(os.environ['DATABASE_URL'])
    database = 'threatlens_test' if test else url.database
    owner = url.set(username='postgres', password=os.environ['POSTGRES_PASSWORD'], database=database)
    if test:
        with psycopg.connect(host=url.host, port=url.port, user='postgres', password=os.environ['POSTGRES_PASSWORD'], dbname='postgres', autocommit=True) as db:
            if not db.execute('SELECT 1 FROM pg_database WHERE datname=%s', [database]).fetchone():
                db.execute('CREATE DATABASE threatlens_test')
    os.environ['DATABASE_URL'] = owner.render_as_string(hide_password=False)
    from app.config import settings
    settings.cache_clear()
    config = Config(str(ROOT / 'backend/alembic.ini'))
    config.set_main_option('script_location', str(ROOT / 'backend/migrations'))
    command.upgrade(config, 'head')
    with create_engine(owner).begin() as db:
        db.execute(text((ROOT / 'deploy/grants.sql').read_text()))
    os.environ['DATABASE_URL'] = url.set(database=database).render_as_string(hide_password=False)
    return os.environ['DATABASE_URL']


if __name__ == '__main__':
    action, *args = sys.argv[1:]
    if action == 'migrate':
        migrate()
        print('Migration and least-privilege grants applied.')
    elif action == 'test':
        os.environ['TEST_DATABASE_URL'] = migrate(test=True)
        os.environ['TEST_MODE'] = 'true'
        raise SystemExit(subprocess.call([sys.executable, '-m', 'pytest', *args], cwd=ROOT / 'backend'))
    elif action == 'api':
        raise SystemExit(subprocess.call([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8100', *args], cwd=ROOT / 'backend'))
    elif action == 'worker':
        raise SystemExit(subprocess.call([sys.executable, '-m', 'celery', '-A', 'app.tasks.celery', 'worker', '--pool=solo', '--loglevel=INFO', *args], cwd=ROOT / 'backend'))
    elif action == 'scheduler':
        raise SystemExit(subprocess.call([sys.executable, '-m', 'celery', '-A', 'app.tasks.celery', 'beat', '--loglevel=INFO', '--schedule='+str(ROOT/'artifacts/celerybeat')], cwd=ROOT / 'backend'))
    elif action == 'cli':
        raise SystemExit(subprocess.call([sys.executable, '-m', 'app.cli', *args], cwd=ROOT / 'backend'))
    else:
        raise SystemExit('Use migrate, test, api, worker, scheduler or cli')
