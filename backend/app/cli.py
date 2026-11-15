import argparse
import getpass
import json

from sqlalchemy import select

from .db import Session
from .feeds import CATALOG
from .models import Feed, User
from .security import audit, digest, hasher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['create-admin', 'configure-feeds', 'verify-audit'])
    parser.add_argument('--email')
    args = parser.parse_args()
    with Session.begin() as db:
        if args.command == 'create-admin':
            if not args.email:
                raise SystemExit('--email required')
            password = getpass.getpass('New administrator password (14+ characters): ')
            if len(password) < 14:
                raise SystemExit('Password too short')
            user = User(email=args.email.lower(), name='Administrator', password_hash=hasher.hash(password), role='administrator')
            db.add(user)
            db.flush()
            audit(db, user.id, 'user.bootstrap', user.id)
            print('Administrator created. No credentials were printed.')
        elif args.command == 'configure-feeds':
            for name, adapter, url, interval, reliability in CATALOG:
                if not db.scalar(select(Feed).where(Feed.name == name)):
                    feed = Feed(name=name, adapter=adapter, url=url, interval_seconds=interval, reliability=reliability)
                    db.add(feed)
                    db.flush()
                    audit(db, None, 'feed.configured', feed.id)
            print('Six public feed configurations added; operating status requires successful polling.')
        else:
            from .models import Audit
            rows = db.scalars(select(Audit)).all()
            invalid = [r.id for r in rows if digest(json.dumps(r.data, sort_keys=True, separators=(',', ':'))) != r.digest]
            print(json.dumps({'checked': len(rows), 'invalid': invalid}))
            if invalid:
                raise SystemExit(1)


if __name__ == '__main__':
    main()
