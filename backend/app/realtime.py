"""Shared WebSocket authorization and authentication audit boundaries."""
from typing import Annotated

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .db import Session
from .models import Incident
from .security import PERMISSIONS, audit, decode_user


class Hello(BaseModel):
    model_config = ConfigDict(extra='forbid')
    access_token: str = Field(min_length=1, max_length=4096)
    channels: list[Annotated[str, Field(min_length=1, max_length=100)]] = Field(min_length=1, max_length=20)


def authorize_channels(db, user, channels):
    for channel in channels:
        if channel in ('alerts.stream', 'indicators.high_severity') and user.role in PERMISSIONS['search']:
            continue
        if channel == 'system.health' and user.role in PERMISSIONS['feed']:
            continue
        if channel.startswith('incidents.') and user.role in PERMISSIONS['incident']:
            if db.get(Incident, channel[len('incidents.'):]) is not None:
                continue
        raise HTTPException(403, 'Channel denied')


def authenticate(token, channels=None):
    with Session.begin() as db:
        user = decode_user(token, db)
        if channels is not None:
            authorize_channels(db, user, channels)
            audit(db, user.id, 'auth.websocket_connected', data={'channels': channels})
        return user.id, user.role


def record_disconnect(identity, accepted):
    with Session.begin() as db:
        audit(db, identity, 'auth.websocket_disconnected' if accepted else 'auth.websocket_rejected')
