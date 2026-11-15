import base64
import json
import secrets
from datetime import timedelta
from types import SimpleNamespace

import jwt
import pytest
import stix2
from fastapi import HTTPException

from app.config import settings
from app.models import now
from app.reporting import csv_export, stix_export
from app.schemas import EventCreate, FeedCreate, IndicatorPatch, UserCreate
from app.security import PERMISSIONS, ROLES, decode_user, decrypt, encrypt, hasher, require


def test_argon2_and_aes256_authentication(monkeypatch):
    password=secrets.token_urlsafe(24)
    hashed=hasher.hash(password)
    assert hashed.startswith('$argon2id$') and hasher.verify(hashed,password)
    monkeypatch.setattr(settings(),'encryption_key',base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    first,second=encrypt(password),encrypt(password)
    assert first!=second and decrypt(first)==password
    raw=bytearray(base64.urlsafe_b64decode(first));raw[-1]^=1
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        decrypt(base64.urlsafe_b64encode(raw).decode())


def test_feed_secret_can_be_stored_as_aes256_ciphertext_on_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(settings(), 'encryption_key', base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setattr(settings(), 'secrets_dir', str(tmp_path))
    credential = 'controlled-feed-key-' + secrets.token_hex(8)
    (tmp_path / 'feed_key.enc').write_text(encrypt(credential))
    stored = (tmp_path / 'feed_key.enc').read_text()
    assert credential not in stored
    assert settings().secret('feed_key') == credential
    (tmp_path / 'legacy_key').write_text(credential)
    assert settings().secret('legacy_key') == credential


def test_mfa_secret_is_ciphertext_in_postgresql(client, db, accounts, monkeypatch):
    from sqlalchemy import text
    monkeypatch.setattr(settings(), 'encryption_key', base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    user, headers, password = accounts['administrator']
    response = client.post('/api/v1/auth/mfa/setup', headers=headers, json={'password': password})
    assert response.status_code == 200, response.text
    secret = response.json()['provisioning_uri'].split('secret=')[1].split('&')[0]
    stored = db.execute(text('SELECT mfa_secret FROM users WHERE id = :id'), {'id': user.id}).scalar_one()
    assert stored != secret and secret not in stored
    assert decrypt(stored) == secret


@pytest.mark.parametrize('role',ROLES)
def test_server_permission_boundaries(role):
    user=SimpleNamespace(role=role)
    assert require('dashboard')(user) is user
    assert require('report')(user) is user
    for permission in ('user','feed','search','enrich','incident','audit'):
        if role in PERMISSIONS[permission]:
            assert require(permission)(user) is user
        else:
            with pytest.raises(HTTPException) as exc:
                require(permission)(user)
            assert exc.value.status_code==403


def test_jwt_expiry_audience_disable_and_revocation():
    user=SimpleNamespace(id='test-user',enabled=True,token_version=2)
    db=SimpleNamespace(get=lambda *a:user)
    payload={'sub':user.id,'ver':2,'iat':now(),'exp':now()+timedelta(minutes=5),'iss':'threatlens','aud':'threatlens-api'}
    def token(**changes):
        return jwt.encode({**payload,**changes},settings().signing_key(),algorithm='HS256')
    assert decode_user(token(),db) is user
    for changes in ({'ver':1},{'exp':now()-timedelta(seconds=1)},{'aud':'another-service'},{'iss':'another-issuer'}):
        with pytest.raises(HTTPException) as exc:
            decode_user(token(**changes),db)
        assert exc.value.status_code==401
    user.enabled=False
    with pytest.raises(HTTPException):decode_user(token(),db)


def test_export_safety_and_stix_schema_without_database():
    ioc=SimpleNamespace(type='email',value='=formula@example.org',score=30,confidence=0,tlp='clear',status='active',tags=[],first_seen=now())
    csv=csv_export([ioc])
    assert "'=formula@example.org" in csv
    bundle=stix2.parse(json.dumps(stix_export([ioc])))
    assert bundle.type=='bundle'
    indicator=next(o for o in bundle.objects if o.type=='indicator')
    assert indicator.pattern_type=='stix' and indicator.spec_version=='2.1'


@pytest.mark.parametrize('value',['\n=CONTROLLED','  +CONTROLLED','\t@CONTROLLED'])
def test_csv_controls_and_whitespace_cannot_hide_formula_prefix(value):
    import csv
    import io
    ioc=SimpleNamespace(type='domain',value='example.org',score=0,confidence=0,tlp='clear',status='active',tags=[value])
    rows=list(csv.reader(io.StringIO(csv_export([ioc]))))
    assert rows[1][-1].startswith("'")


def test_validation_prevents_privilege_fields_and_invalid_events():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):UserCreate(email='a@example.org',name='A',password='long-enough-password',role='superuser')
    with pytest.raises(ValidationError):IndicatorPatch(score=100)
    with pytest.raises(ValidationError):FeedCreate(name='test',adapter='json',url='https://example.org',interval_seconds=1)
    with pytest.raises(ValidationError):EventCreate(source='test',external_id='one',occurred_at='2026-07-01T12:00:00',asset='test',observables=[{'type':'ip','value':'192.0.2.1'}])
