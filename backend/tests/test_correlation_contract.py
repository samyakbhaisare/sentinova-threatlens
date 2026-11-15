"""Controlled correlation unit scenarios with persistence boundary doubles."""
from types import SimpleNamespace

from sqlalchemy.sql.dml import Insert

from app.correlation import correlate
from app.models import AlertRule, IncidentLink, Indicator, Notification, Provenance, SecurityEvent, Timeline, User, now


class CorrelationSession:
    def __init__(self,match=True,routed=True):
        self.indicator=Indicator(id='ioc',type='domain',value='controlled.example.org',status='active',category='malware',reputation=90,confidence=90,last_seen=now())
        self.event=SecurityEvent(id='event',observables=[{'type':'domain','value':'controlled.example.org' if match else 'unrelated.example.org'}])
        self.rule=AlertRule(id='rule',name='Controlled',enabled=True,min_score=70,min_sightings=1,category='malware',feed_id='feed',recipient_id='analyst' if routed else None)
        self.sightings=set();self.alerts=set();self.added=[]

    def scalars(self, statement):
        entity=statement.column_descriptions[0]['entity']
        values={Indicator:[self.indicator],SecurityEvent:[self.event],AlertRule:[self.rule],
            IncidentLink:[SimpleNamespace(incident_id='incident')],Provenance:['feed'],User:['analyst','responder']}[entity]
        return Result(values)

    def scalar(self, statement):
        if not isinstance(statement,Insert):return len(self.sightings)
        collection=self.sightings if statement.table.name=='sightings' else self.alerts
        if collection:return None
        collection.add('controlled')
        return 'new-'+statement.table.name

    def add(self,record):self.added.append(record)


class Result(list):
    def all(self):return list(self)


def test_bidirectional_match_is_idempotent_and_captures_incident_and_recipient():
    db=CorrelationSession()
    correlate(db,event=db.event)
    correlate(db,indicator=db.indicator)
    timelines=[row for row in db.added if isinstance(row,Timeline)]
    notifications=[row for row in db.added if isinstance(row,Notification)]
    assert len(db.sightings)==1 and len(db.alerts)==1
    assert len(timelines)==1 and timelines[0].data=={'event_id':'event','indicator_id':'ioc'}
    assert len(notifications)==1 and notifications[0].user_id=='analyst'


def test_unrelated_and_whitelisted_indicators_do_not_raise_alerts():
    db=CorrelationSession(match=False)
    correlate(db,indicator=db.indicator)
    assert not db.sightings and not db.alerts
    db=CorrelationSession();db.indicator.status='whitelisted'
    correlate(db,indicator=db.indicator)
    assert not db.added and not db.alerts


def test_team_routing_resolves_operational_recipients():
    db=CorrelationSession(routed=False)
    correlate(db,indicator=db.indicator)
    assert {row.user_id for row in db.added if isinstance(row,Notification)}=={'analyst','responder'}
