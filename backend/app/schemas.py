from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from .intelligence import canonical

Role = Literal['administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst', 'executive']
TLP = Literal['clear', 'green', 'amber', 'red']


class Schema(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Login(Schema):
    email: EmailStr
    password: str = Field(max_length=256)
    totp: str | None = Field(default=None, pattern=r'^\d{6}$')


class UserCreate(Schema):
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=14, max_length=256)
    role: Role = 'soc_analyst'


class UserPatch(Schema):
    role: Role | None = None
    enabled: bool | None = None


class PasswordReset(Schema):
    token: str = Field(min_length=32, max_length=200)
    password: str = Field(min_length=14, max_length=256)


class MFA(Schema):
    password: str = Field(max_length=256)
    code: str | None = Field(default=None, pattern=r'^\d{6}$')


class FeedCreate(Schema):
    name: str = Field(min_length=1, max_length=120)
    adapter: str = Field(max_length=32)
    url: str = Field(max_length=2048)
    secret_ref: str = Field(default='', pattern=r'^[a-zA-Z0-9_]*$', max_length=100)
    interval_seconds: int = Field(default=3600, ge=300, le=2592000)
    ttl_days: int = Field(default=30, ge=1, le=3650)
    reliability: int = Field(default=50, ge=0, le=100)


class FeedPatch(Schema):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=300, le=2592000)
    ttl_days: int | None = Field(default=None, ge=1, le=3650)


class Observable(Schema):
    type: Literal['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'cve']
    value: str = Field(max_length=2048)

    @field_validator('value')
    @classmethod
    def normalize(cls, value, info):
        if 'type' not in info.data:
            raise ValueError('Valid observable type required')
        return canonical(info.data['type'], value)


class IndicatorCreate(Observable):
    confidence: int = Field(default=0, ge=0, le=100)
    category: str = Field(default='unknown', max_length=100)
    tlp: TLP = 'clear'


class IndicatorPatch(Schema):
    expected_version: int | None = Field(default=None, ge=1)
    annotation_tlp: TLP | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    techniques: list[str] | None = Field(default=None, max_length=50)
    tlp: Literal['clear', 'green', 'amber', 'red'] | None = None
    status: Literal['active', 'expired', 'whitelisted', 'under_review'] | None = None
    notes: str | None = Field(default=None, max_length=20000)
    notes_tlp: TLP | None = None
    ttl_days: int | None = Field(default=None, ge=1, le=3650)

    @field_validator('techniques')
    @classmethod
    def techniques_valid(cls, value):
        import re
        if value and any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?', t) for t in value):
            raise ValueError('Invalid ATT&CK technique ID')
        return value

    @field_validator('tags')
    @classmethod
    def tags_valid(cls, value):
        if value and any(not tag.strip() or len(tag) > 80 for tag in value):
            raise ValueError('Tags must contain 1–80 characters')
        return value


class Edge(Schema):
    target_id: str = Field(max_length=36)
    kind: Literal['resolves-to', 'communicates-with', 'drops', 'related-to']


class GeoObservation(Schema):
    latitude: float = Field(ge=-90, le=90, strict=True, allow_inf_nan=False)
    longitude: float = Field(ge=-180, le=180, strict=True, allow_inf_nan=False)
    country: str = Field(pattern=r'^[A-Z]{2}$')
    source: str = Field(min_length=1, max_length=150)
    observed_at: datetime

    @field_validator('observed_at')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError('Geolocation observation timezone required')
        return value


class EventCreate(Schema):
    source: str = Field(min_length=1, max_length=100)
    external_id: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    asset: str = Field(min_length=1, max_length=200)
    observables: list[Observable] = Field(min_length=1, max_length=100)
    details: dict = Field(default_factory=dict)
    controlled_test: bool = False
    tlp: TLP = 'amber'

    @field_validator('details')
    @classmethod
    def validate_details(cls, value):
        import json
        json.dumps(value, allow_nan=False)
        if 'target_geo' in value:
            value = {**value, 'target_geo': GeoObservation.model_validate(value['target_geo']).model_dump(mode='json')}
        return value

    @field_validator('occurred_at')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError('Timezone required')
        return value


class RuleCreate(Schema):
    name: str = Field(min_length=1, max_length=150)
    min_score: int = Field(default=70, ge=0, le=100)
    min_sightings: int = Field(default=1, ge=0, le=100000)
    category: str | None = Field(default=None, max_length=100)
    feed_id: str | None = Field(default=None, max_length=36)
    recipient_id: str | None = Field(default=None, max_length=36)
    enabled: bool = True


class RulePatch(Schema):
    expected_version: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=150)
    min_score: int | None = Field(default=None, ge=0, le=100)
    min_sightings: int | None = Field(default=None, ge=0, le=100000)
    category: str | None = Field(default=None, max_length=100)
    feed_id: str | None = Field(default=None, max_length=36)
    recipient_id: str | None = Field(default=None, max_length=36)
    enabled: bool | None = None

    @model_validator(mode='after')
    def nonnullable_fields(self):
        for key in ('name', 'min_score', 'min_sightings', 'enabled'):
            if key in self.model_fields_set and getattr(self, key) is None:
                raise ValueError(f'{key} cannot be null')
        return self


class AlertPatch(Schema):
    expected_version: int | None = Field(default=None, ge=1)
    state: Literal['new', 'acknowledged', 'in-progress', 'resolved', 'closed'] | None = None
    assignee_id: str | None = Field(default=None, max_length=36)


class IncidentCreate(Schema):
    title: str = Field(min_length=1, max_length=200)
    indicator_id: str = Field(max_length=36)
    alert_id: str | None = Field(default=None, max_length=36)
    tlp: TLP = 'amber'


class IncidentLinkCreate(Schema):
    indicator_id: str = Field(max_length=36)
    alert_id: str | None = Field(default=None, max_length=36)


class IncidentPatch(Schema):
    expected_version: int | None = Field(default=None, ge=1)
    tlp: TLP | None = None
    state: Literal['open', 'resolved', 'closed'] | None = None
    owner_id: str | None = Field(default=None, max_length=36)
    checklist: dict[str, bool] | None = None


class Note(Schema):
    text: str = Field(min_length=1, max_length=20000)
    tlp: TLP = 'amber'


class HuntCreate(Schema):
    name: str = Field(min_length=1, max_length=150)
    query: dict[str, str | int] = Field(default_factory=dict)


class Layout(Schema):
    widgets: list[Literal['metrics', 'trends', 'map', 'sources', 'severity']] = Field(max_length=5)


class ReportCreate(Schema):
    title: str = Field(default='Intelligence briefing', max_length=200)
    incident_id: str | None = Field(default=None, max_length=36)
    schedule_hours: int | None = Field(default=None, ge=1, le=8760)
    tlp: TLP = 'amber'


class ReportPatch(Schema):
    expected_version: int | None = Field(default=None, ge=1)
    schedule_hours: int | None = Field(default=None, ge=1, le=8760)
    cancel: bool = False

    @model_validator(mode='after')
    def cancellation_is_exclusive(self):
        if self.cancel and self.schedule_hours is not None:
            raise ValueError('Cancel cannot also enable a schedule')
        return self
