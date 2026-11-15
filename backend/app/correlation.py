from sqlalchemy import func, select, tuple_
from sqlalchemy.dialects.postgresql import insert

from .intelligence import rescore
from .models import Alert, AlertRule, EventObservable, Incident, IncidentLink, Indicator, Notification, Outbox, Provenance, SecurityEvent, Sighting, Timeline, User, uid
from .security import audit
from .classification import highest


def rule_matches(rule, indicator, count, source_ids):
    return (rule.enabled and indicator.status == 'active' and indicator.score >= rule.min_score
            and count >= rule.min_sightings and (not rule.category or rule.category == indicator.category)
            and (not rule.feed_id or rule.feed_id in source_ids))


def correlate(db, indicator=None, event=None):
    indicators = [indicator] if indicator else db.scalars(select(Indicator).where(Indicator.status == 'active', tuple_(Indicator.type, Indicator.value).in_([(o['type'], o['value']) for o in event.observables]))).all()
    for ioc in indicators:
        if ioc.status != 'active':
            continue
        events = [event] if event else db.scalars(select(SecurityEvent).join(EventObservable).where(EventObservable.type == ioc.type, EventObservable.value == ioc.value)).all()
        for ev in events:
            if not any(o['type'] == ioc.type and o['value'] == ioc.value for o in ev.observables):
                continue
            added = db.scalar(insert(Sighting).values(id=uid(), indicator_id=ioc.id, event_id=ev.id).on_conflict_do_nothing().returning(Sighting.id))
            if added:
                audit(db, None, 'correlation.sighting', ioc.id, {'event_id': ev.id})
                for link in db.scalars(select(IncidentLink).join(Incident).where(IncidentLink.indicator_id == ioc.id, Incident.state == 'open')):
                    db.add(Timeline(incident_id=link.incident_id, kind='correlated_event', tlp=highest(ioc.tlp or 'clear', ev.tlp or 'amber'), data={'event_id': ev.id, 'indicator_id': ioc.id}))
                    db.add(Outbox(topic='incidents.' + link.incident_id, object_id=link.incident_id))
        rescore(db, ioc)
        count = db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == ioc.id))
        source_ids = set(db.scalars(select(Provenance.feed_id).where(Provenance.indicator_id == ioc.id)))
        for rule in db.scalars(select(AlertRule).where(AlertRule.enabled.is_(True))):
            if not rule_matches(rule, ioc, count, source_ids):
                continue
            alert_id = db.scalar(insert(Alert).values(id=uid(), indicator_id=ioc.id, rule_id=rule.id, score=ioc.score,
                recipient_id=rule.recipient_id).on_conflict_do_nothing().returning(Alert.id))
            if alert_id:
                audit(db, None, 'alert.created', alert_id, {'indicator_id': ioc.id, 'rule_id': rule.id})
                db.add(Outbox(topic='alerts.stream', object_id=alert_id))
                recipients = [rule.recipient_id] if rule.recipient_id else db.scalars(select(User.id).where(User.enabled.is_(True), User.role.in_(['administrator', 'incident_responder', 'soc_analyst']))).all()
                for recipient in recipients:
                    db.add(Notification(user_id=recipient, alert_id=alert_id))
