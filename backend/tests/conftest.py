import os
import secrets

os.environ.setdefault('JWT_SECRET', secrets.token_urlsafe(48))
os.environ.setdefault('TEST_MODE', 'true')

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def db():
    url = os.environ.get('TEST_DATABASE_URL')
    if not url:
        pytest.skip('TEST_DATABASE_URL is required for real PostgreSQL integration tests')
    if not url.rsplit('/', 1)[-1].startswith('threatlens_test'):
        raise RuntimeError('Tests require a dedicated threatlens_test database')
    from app.db import Base
    from app import models  # noqa: F401
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, join_transaction_mode='create_savepoint', expire_on_commit=False)()
    yield session
    session.close()
    transaction.rollback()
    connection.close()
    engine.dispose()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_db

    def override():
        yield db
        db.commit()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def accounts(db):
    from app.models import User
    from app.security import ROLES, hasher, issue
    password = secrets.token_urlsafe(24)
    result = {}
    for role in ROLES:
        user = User(email=role+'@example.org', name=role, role=role, password_hash=hasher.hash(password))
        db.add(user)
        db.flush()
        token, _ = issue(db, user)
        result[role] = (user, {'Authorization': 'Bearer '+token}, password)
    db.commit()
    return result
