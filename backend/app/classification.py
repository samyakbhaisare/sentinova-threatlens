"""TLP sharing policy; classification is independent of internal operational roles."""
from fastapi import HTTPException
from sqlalchemy import select

from .models import Incident, IncidentLink, Indicator, Timeline

LEVELS = {'clear': 0, 'green': 1, 'amber': 2, 'red': 3}


def highest(*labels):
    values = [label for label in labels if label is not None]
    if any(label not in LEVELS for label in values):
        raise ValueError('Unknown handling label')
    return max(values, key=LEVELS.get, default='clear')


def allowed_labels(role, audience):
    if audience not in ('public', 'internal'):
        raise HTTPException(422, 'Unknown sharing audience')
    if role not in ('administrator', 'security_engineer', 'incident_responder', 'threat_hunter', 'soc_analyst'):
        raise HTTPException(403, 'Intelligence export denied')
    return ['clear'] if audience == 'public' or role == 'soc_analyst' else ['clear', 'green', 'amber']


def ensure_monotonic(current, requested):
    if requested is not None and LEVELS[requested] < LEVELS[current]:
        raise HTTPException(409, 'Handling labels cannot be lowered by an ordinary edit')


def expect_version(row, expected):
    if expected is not None and row.version != expected:
        raise HTTPException(409, 'Record changed; refresh and retry with the current version')


def incident_label(db, incident):
    labels = [incident.tlp]
    labels.extend(db.scalars(select(Indicator.tlp).join(IncidentLink).where(IncidentLink.incident_id == incident.id)))
    labels.extend(db.scalars(select(Timeline.tlp).where(Timeline.incident_id == incident.id)))
    return highest(*labels)


def incident_labels(db, incidents):
    """Batch form of :func:`incident_label` to avoid two queries per row."""
    labels = {incident.id: [incident.tlp] for incident in incidents}
    if not labels:
        return {}
    ids = list(labels)
    links = select(IncidentLink.incident_id, Indicator.tlp).join(Indicator, Indicator.id == IncidentLink.indicator_id)
    for incident_id, tlp in db.execute(links.where(IncidentLink.incident_id.in_(ids))):
        labels[incident_id].append(tlp)
    for incident_id, tlp in db.execute(select(Timeline.incident_id, Timeline.tlp).where(Timeline.incident_id.in_(ids))):
        labels[incident_id].append(tlp)
    return {incident_id: highest(*values) for incident_id, values in labels.items()}


def raise_linked_incidents(db, indicator):
    for incident in db.scalars(select(Incident).join(IncidentLink).where(IncidentLink.indicator_id == indicator.id)):
        incident.tlp = highest(incident.tlp, indicator.tlp)
