import base64
import hashlib
import json
import secrets
from datetime import timedelta
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as DBSession

from .config import settings
from .db import get_db
from .models import Audit, Refresh, User, now, uid

ROLES = ('administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst', 'executive')
PERMISSIONS = {
    'dashboard': set(ROLES), 'report': set(ROLES),
    'search': set(ROLES) - {'executive'},
    'enrich': {'administrator', 'security_engineer', 'incident_responder', 'soc_analyst'},
    'tag': set(ROLES) - {'executive'},
    'feed': {'administrator', 'security_engineer'},
    'user': {'administrator'},
    'alert': set(ROLES) - {'executive'},
    'incident': {'administrator', 'incident_responder', 'soc_analyst', 'threat_hunter'},
    'hunt': set(ROLES) - {'executive'},
    'export': set(ROLES) - {'executive'},
    'audit': {'administrator', 'security_engineer', 'incident_responder'},
}
hasher = PasswordHasher()
bearer = HTTPBearer(auto_error=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def audit(db, actor, action, object_id=None, data=None, correlation_id=None):
    payload = {'actor': actor, 'action': action, 'object': object_id, 'data': data or {}, 'time': now().isoformat()}
    db.add(Audit(actor_id=actor, action=action, object_id=object_id, correlation_id=correlation_id or uid(), data=payload,
                 digest=digest(json.dumps(payload, sort_keys=True, separators=(',', ':')))))


def issue(db, user, family=None):
    access = jwt.encode({'sub': user.id, 'ver': user.token_version, 'iat': now(), 'exp': now() + timedelta(minutes=10), 'iss': 'threatlens', 'aud': 'threatlens-api'}, settings().signing_key(), algorithm='HS256')
    raw = secrets.token_urlsafe(48)
    db.add(Refresh(user_id=user.id, digest=digest(raw), family=family or uid(), expires_at=now() + timedelta(days=7)))
    return access, raw


def decode_user(token, db):
    try:
        claims = jwt.decode(token, settings().signing_key(), algorithms=['HS256'], issuer='threatlens', audience='threatlens-api', options={'require': ['exp', 'sub', 'iat', 'ver']})
        user = db.get(User, claims['sub'])
        if not user or not user.enabled or user.token_version != claims['ver']:
            raise ValueError('revoked')
        return user
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(401, 'Invalid or expired credentials') from None


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: DBSession = Depends(get_db)):
    if not credentials:
        raise HTTPException(401, 'Authentication required')
    return decode_user(credentials.credentials, db)


def require(permission):
    def dependency(user: User = Depends(current_user)):
        if user.role not in PERMISSIONS.get(permission, set()):
            raise HTTPException(403, 'Permission denied')
        return user
    return dependency


def stateless_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: DBSession = Depends(get_db)):
    """Authenticate and then release the pooled connection before slow I/O.

    Read-only endpoints that call external services (for example Elasticsearch)
    must not keep a PostgreSQL connection checked out while waiting on that
    service: under concurrency the pool would be exhausted by I/O wait rather
    than by real database work.  Sessions bound to an externally managed
    ``Connection`` (the test transaction) are left untouched so test isolation
    is preserved.
    """
    if not credentials:
        raise HTTPException(401, 'Authentication required')
    user = decode_user(credentials.credentials, db)
    if isinstance(db.get_bind(), Engine):
        db.close()
    return user


def require_stateless(permission):
    def dependency(user: User = Depends(stateless_user)):
        if user.role not in PERMISSIONS.get(permission, set()):
            raise HTTPException(403, 'Permission denied')
        return user
    return dependency


def encrypt(value):
    config = settings()
    raw = Path(config.encryption_key_file).read_text().strip() if config.encryption_key_file else config.encryption_key
    key = base64.urlsafe_b64decode(raw)
    if len(key) != 32:
        raise RuntimeError('AES-256 key must decode to 32 bytes')
    nonce = secrets.token_bytes(12)
    return base64.urlsafe_b64encode(nonce + AESGCM(key).encrypt(nonce, value.encode(), b'threatlens')).decode()


def decrypt(value):
    config = settings()
    raw = Path(config.encryption_key_file).read_text().strip() if config.encryption_key_file else config.encryption_key
    key = base64.urlsafe_b64decode(raw)
    value = base64.urlsafe_b64decode(value)
    return AESGCM(key).decrypt(value[:12], value[12:], b'threatlens').decode()
