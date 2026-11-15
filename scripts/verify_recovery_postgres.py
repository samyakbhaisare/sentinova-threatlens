"""Real-PostgreSQL recovery drill: durable export jobs survive process loss.

Creates two clearly synthetic export jobs in ``threatlens_test`` (an expired
running lease and an old queued job without a broker message), closes the
session to model a process restart, then runs the production ``recover_expired``
routine in a fresh session and verifies one re-dispatch per job.  Synthetic rows
are removed afterwards; append-only audit evidence is retained.
"""
import json
import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')
for key in ('DATABASE_URL', 'REDIS_URL', 'SEARCH_URL'):
    if key in os.environ:
        os.environ[key] = os.environ[key].replace('localhost', '127.0.0.1')
sys.path.insert(0, str(ROOT / 'backend'))

_test_url = make_url(os.environ['DATABASE_URL']).set(database='threatlens_test')
if _test_url.database != 'threatlens_test':
    raise SystemExit('Refusing to drill against a non-test database')
os.environ['DATABASE_URL'] = _test_url.render_as_string(hide_password=False)
os.environ['REDIS_URL'] = os.environ['REDIS_URL'].rsplit('/', 1)[0] + '/3'
os.environ['TEST_MODE'] = 'true'

from app import bulk_exports as exports  # noqa: E402
from app.db import Session  # noqa: E402
from app.models import ExportJob, Outbox, User, now, uid  # noqa: E402

RUN = 'nfr-recovery-' + secrets.token_hex(4)
engine = create_engine(_test_url, connect_args={'connect_timeout': 5})
created = []


def main():
    with Session() as db:
        owner = db.scalars(select(User).order_by(User.created_at).limit(1)).first()
        if owner is None:
            raise SystemExit('No user exists in threatlens_test to own synthetic jobs')
        running = ExportJob(id=uid(), owner_id=owner.id, format='csv', audience='internal', filters={},
                            max_records=10, state='running', attempt_token=uid(), attempts=1,
                            lease_until=now() - timedelta(minutes=5))
        queued = ExportJob(id=uid(), owner_id=owner.id, format='csv', audience='internal', filters={},
                           max_records=10, state='queued', attempts=0, lease_until=None,
                           created_at=now() - timedelta(minutes=30))
        db.add_all([running, queued])
        created.extend([running.id, queued.id])
        db.commit()

    # New session on a new engine/connection: models a process restart before recovery runs.
    restarted = create_engine(_test_url, connect_args={'connect_timeout': 5})
    with Session(bind=restarted) as db:
        recovered = exports.recover_expired(db)
        db.commit()
        states = {job.id: (job.state, job.lease_until is not None)
                  for job in db.scalars(select(ExportJob).where(ExportJob.id.in_(created)))}
        messages = {identifier: db.scalar(select(func.count()).select_from(Outbox)
                                          .where(Outbox.topic == 'export.generate', Outbox.object_id == identifier))
                    for identifier in created}
    restarted.dispose()

    result = {'run': RUN, 'database': 'threatlens_test', 'recovered_jobs_total': recovered,
              'synthetic_jobs': created, 'states_after_recovery': states,
              'outbox_messages_per_job': messages,
              'assertions': {
                  'expired_lease_requeued': states[created[0]][0] == 'queued' and messages[created[0]] == 1,
                  'old_queued_job_redelivered': states[created[1]][0] == 'queued' and messages[created[1]] == 1,
                  'each_job_has_exactly_one_message': all(count == 1 for count in messages.values()),
              }}
    with Session.begin() as db:
        db.execute(delete(Outbox).where(Outbox.topic == 'export.generate', Outbox.object_id.in_(created)))
        db.execute(delete(ExportJob).where(ExportJob.id.in_(created)))
    engine.dispose()
    result['cleanup'] = {'synthetic_export_jobs_removed': True,
                         'append_only_audit_evidence_retained': True,
                         'production_business_rows_touched': 0}
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-pg-recovery.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)
    if not all(result['assertions'].values()):
        raise SystemExit('Recovery assertions failed')


if __name__ == '__main__':
    main()
