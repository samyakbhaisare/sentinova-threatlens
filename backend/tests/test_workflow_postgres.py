"""Complete SOC workflow coverage on real PostgreSQL.

Every fixture here is synthetic and lives inside the per-test transaction that the
``db`` fixture rolls back.  Nothing is written to the production database.
"""
import json
from datetime import timedelta

import pytest
from sqlalchemy import event, func, select, update

from app.models import (
    Alert,
    AlertRule,
    Audit,
    Enrichment,
    Feed,
    Incident,
    IncidentLink,
    Indicator,
    Notification,
    Outbox,
    Provenance,
    SecurityEvent,
    Sighting,
    Timeline,
    now,
)
from app.security import digest as sha256_text

pytestmark = pytest.mark.integration


def make_indicator(db, value='203.0.113.10', **overrides):
    values = dict(
        type='ip',
        value=value,
        score=80,
        confidence=90,
        reputation=90,
        category='malware',
        tlp='amber',
        first_seen=now(),
        last_seen=now(),
        expires_at=now() + timedelta(days=30),
    )
    values.update(overrides)
    row = Indicator(**values)
    db.add(row)
    db.flush()
    return row


def post_event(client, headers, value, external_id='controlled-event', source='controlled-workflow', **extra):
    payload = {
        'source': source,
        'external_id': external_id,
        'occurred_at': now().isoformat(),
        'asset': 'controlled-workstation',
        'observables': [{'type': 'ip', 'value': value}],
        'controlled_test': True,
    }
    payload.update(extra)
    return client.post('/api/v1/events', headers=headers, json=payload)


def make_feed(db, name):
    row = Feed(name=name, adapter='json', url='internal', enabled=False, reliability=90)
    db.add(row)
    db.flush()
    return row


def test_rule_dimensions_sighting_threshold_dedupe_and_fanout(client, accounts, db):
    """Only the rule whose score, sightings, category and feed dimensions all match fires."""
    admin, admin_auth, _ = accounts['administrator']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    hunter, hunter_auth, _ = accounts['threat_hunter']
    ioc = make_indicator(db)
    feed_a = make_feed(db, 'CONTROLLED DIMENSION A')
    feed_b = make_feed(db, 'CONTROLLED DIMENSION B')
    db.add(Provenance(indicator_id=ioc.id, feed_id=feed_a.id, confidence=90, reference='CONTROLLED'))
    # Isolate from rules left in the shared isolated test database by other suites.
    db.execute(update(AlertRule).values(enabled=False))

    expected = client.post('/api/v1/alert-rules', headers=admin_auth, json={
        'name': 'CONTROLLED matching rule', 'min_score': 50, 'min_sightings': 2,
        'category': 'malware', 'feed_id': feed_a.id, 'recipient_id': analyst.id,
    })
    assert expected.status_code == 201, expected.text
    expected_id = expected.json()['id']

    rejected = [
        {'name': 'CONTROLLED disabled', 'min_sightings': 1, 'recipient_id': analyst.id, 'enabled': False},
        {'name': 'CONTROLLED score ceiling', 'min_score': 99, 'min_sightings': 1, 'recipient_id': analyst.id},
        {'name': 'CONTROLLED wrong category', 'min_sightings': 1, 'category': 'phishing', 'recipient_id': analyst.id},
        {'name': 'CONTROLLED wrong feed', 'min_sightings': 1, 'feed_id': feed_b.id, 'recipient_id': analyst.id},
    ]
    for rule in rejected:
        assert client.post('/api/v1/alert-rules', headers=admin_auth, json=rule).status_code == 201

    first = post_event(client, admin_auth, ioc.value, external_id='controlled-1')
    assert first.status_code == 201, first.text
    assert first.json()['replayed'] is False
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == ioc.id)) == 1
    assert db.scalar(select(func.count()).select_from(Alert).where(Alert.indicator_id == ioc.id)) == 0  # min_sightings=2 not reached

    second_at = now().isoformat()
    second = post_event(client, admin_auth, ioc.value, external_id='controlled-2', occurred_at=second_at)
    assert second.status_code == 201 and second.json()['replayed'] is False
    db.expire_all()
    alerts = db.scalars(select(Alert).where(Alert.indicator_id == ioc.id)).all()
    assert len(alerts) == 1
    assert alerts[0].rule_id == expected_id
    assert alerts[0].recipient_id == analyst.id
    assert db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == ioc.id)) == 2
    assert db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == analyst.id)) == 1
    assert db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == hunter.id)) == 0
    assert db.scalar(select(func.count()).select_from(Outbox).where(Outbox.topic == 'alerts.stream', Outbox.object_id == alerts[0].id)) == 1

    replay = post_event(client, admin_auth, ioc.value, external_id='controlled-2', occurred_at=second_at)
    assert replay.status_code == 201 and replay.json()['replayed'] is True
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Alert).where(Alert.indicator_id == ioc.id)) == 1
    assert db.scalar(select(func.count()).select_from(Sighting).where(Sighting.indicator_id == ioc.id)) == 2

    visible = client.get('/api/v1/alerts', headers=analyst_auth).json()['items']
    assert [row['id'] for row in visible] == [alerts[0].id]
    assert client.get('/api/v1/alerts', headers=hunter_auth).json()['items'] == []
    assert client.get('/api/v1/alerts', headers=admin_auth).json()['items']

    inbox = client.get('/api/v1/notifications', headers=analyst_auth).json()['items']
    assert len(inbox) == 1 and inbox[0]['read'] is False
    assert client.patch('/api/v1/notifications/' + inbox[0]['id'] + '/read', headers=hunter_auth).status_code == 403
    marked = client.patch('/api/v1/notifications/' + inbox[0]['id'] + '/read', headers=analyst_auth)
    assert marked.status_code == 200 and marked.json()['read'] is True

    db.expire_all()
    created = db.scalars(select(Audit).where(Audit.action == 'alert.created', Audit.object_id == alerts[0].id)).all()
    assert len(created) == 1
    payload = created[0].data
    assert created[0].digest == sha256_text(json.dumps(payload, sort_keys=True, separators=(',', ':')))
    assert payload['object'] == alerts[0].id


def test_alert_lifecycle_limited_role_self_assignment_and_routing(client, accounts, db):
    """Engineer/hunter triage must not deadlock on an unassigned alert routed to them."""
    engineer, engineer_auth, _ = accounts['security_engineer']
    hunter, hunter_auth, _ = accounts['threat_hunter']
    admin, admin_auth, _ = accounts['administrator']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    ioc = make_indicator(db, tlp='amber')
    rule = AlertRule(name='CONTROLLED routed rule', min_score=50, recipient_id=engineer.id)
    db.add(rule)
    db.flush()
    alert = Alert(indicator_id=ioc.id, rule_id=rule.id, score=80, recipient_id=engineer.id)
    db.add(alert)
    db.flush()
    path = '/api/v1/alerts/' + alert.id

    # Another analyst cannot see or touch an alert routed elsewhere.
    assert client.get(path + '/history', headers=hunter_auth).status_code == 403
    assert client.patch(path, headers=hunter_auth, json={'assignee_id': hunter.id}).status_code == 403
    assert client.patch(path, headers=analyst_auth, json={'state': 'acknowledged'}).status_code == 403

    # Unassigned alert routed to the engineer: claiming it must be possible.
    claimed = client.patch(path, headers=engineer_auth, json={'assignee_id': engineer.id, 'state': 'acknowledged'})
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body['assignee_id'] == engineer.id and body['state'] == 'acknowledged'

    # Limited role may not hand the alert to somebody else or resolve it.
    assert client.patch(path, headers=engineer_auth, json={'assignee_id': analyst.id}).status_code == 403
    assert client.patch(path, headers=engineer_auth, json={'state': 'resolved'}).status_code == 403

    # Administrator drives the remaining lifecycle and cannot skip steps.
    assert client.patch(path, headers=admin_auth, json={'state': 'in-progress'}).status_code == 200
    assert client.patch(path, headers=admin_auth, json={'state': 'closed'}).status_code == 409
    assert client.patch(path, headers=admin_auth, json={'state': 'resolved'}).status_code == 200
    closed = client.patch(path, headers=admin_auth, json={'state': 'closed'})
    assert closed.status_code == 200 and closed.json()['state'] == 'closed'

    history = client.get(path + '/history', headers=engineer_auth)
    assert history.status_code == 200
    states = [item['data']['data'].get('after', {}).get('state') for item in history.json()['items']]
    assert 'acknowledged' in states and 'closed' in states
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(Audit).where(Audit.action == 'alert.updated', Audit.object_id == alert.id)) >= 4


def test_incident_workflow_evidence_timeline_and_dashboard(client, accounts, db):
    admin, admin_auth, _ = accounts['administrator']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    hunter, hunter_auth, _ = accounts['threat_hunter']
    responder, responder_auth, _ = accounts['incident_responder']
    executive, executive_auth, _ = accounts['executive']
    ioc = make_indicator(db, value='203.0.113.20')
    second_ioc = make_indicator(db, value='203.0.113.21', tlp='green')
    rule = AlertRule(name='CONTROLLED incident rule', min_score=50, recipient_id=analyst.id)
    db.add(rule)
    db.flush()
    alert = Alert(indicator_id=ioc.id, rule_id=rule.id, score=80, recipient_id=analyst.id, assignee_id=analyst.id)
    db.add(alert)
    db.flush()
    db.add(Enrichment(indicator_id=ioc.id, provider='ipwhois', data={'latitude': 51.5, 'longitude': -0.1, 'country': 'GB'}, expires_at=now() + timedelta(days=1)))
    db.flush()

    event = post_event(client, admin_auth, ioc.value, external_id='controlled-incident-event')
    assert event.status_code == 201
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.external_id == 'controlled-incident-event')) == 1

    created = client.post('/api/v1/incidents', headers=analyst_auth, json={
        'title': 'CONTROLLED incident workflow', 'indicator_id': ioc.id, 'alert_id': alert.id, 'tlp': 'amber',
    })
    assert created.status_code == 201, created.text
    incident = created.json()
    path = '/api/v1/incidents/' + incident['id']
    assert incident['owner_id'] == analyst.id and incident['creator_id'] == analyst.id
    assert incident['tlp'] == 'amber'

    # Evidence linking: creator can, an unrelated hunter can read but not write.
    linked = client.post(path + '/links', headers=analyst_auth, json={'indicator_id': second_ioc.id})
    assert linked.status_code == 201 and linked.json()['replayed'] is False
    assert client.post(path + '/links', headers=analyst_auth, json={'indicator_id': second_ioc.id}).json()['replayed'] is True
    assert client.post(path + '/links', headers=hunter_auth, json={'indicator_id': second_ioc.id}).status_code == 403

    note = client.post(path + '/timeline', headers=analyst_auth, json={'text': 'CONTROLLED analyst note', 'tlp': 'amber'})
    assert note.status_code == 201
    assert client.post(path + '/timeline', headers=hunter_auth, json={'text': 'CONTROLLED outsider note'}).status_code == 403

    # Alert changes flow into the linked incident timeline.
    assert client.patch(path + '/timeline', headers=admin_auth, json={'text': 'ignored'}).status_code == 405
    acked = client.patch('/api/v1/alerts/' + alert.id, headers=admin_auth, json={'state': 'acknowledged'})
    assert acked.status_code == 200

    timeline = client.get(path + '/timeline', headers=hunter_auth)
    assert timeline.status_code == 200
    payload = timeline.json()
    kinds = {item['kind'] for item in payload['items']}
    assert {'opened', 'evidence_linked', 'analyst_note', 'alert_updated'} <= kinds
    assert {link['indicator_id'] for link in payload['links']} == {ioc.id, second_ioc.id}
    assert any(item['kind'] == 'linked_event' and item['data'].get('event_id') for item in payload['items'])

    # Only responders may change incident state or ownership.
    assert client.patch(path, headers=analyst_auth, json={'state': 'resolved'}).status_code == 403
    assert client.patch(path, headers=hunter_auth, json={'state': 'resolved'}).status_code == 403
    assert client.patch(path, headers=admin_auth, json={'state': 'closed'}).status_code == 409
    assert client.patch(path, headers=admin_auth, json={'state': 'resolved'}).status_code == 200
    assert client.patch(path, headers=admin_auth, json={'owner_id': analyst.id}).status_code == 422
    assert client.patch(path, headers=admin_auth, json={'owner_id': responder.id}).status_code == 200
    assert client.patch(path, headers=admin_auth, json={'state': 'closed'}).status_code == 200

    # Dashboard aggregate reflects the new workflow state without hiding raw queues from operators.
    dashboard = client.get('/api/v1/dashboard', headers=admin_auth)
    assert dashboard.status_code == 200
    metrics = dashboard.json()
    assert metrics['active_indicators'] >= 2
    assert metrics['alerts'].get('acknowledged', 0) >= 1
    assert metrics['incidents'].get('closed', 0) >= 1
    assert any(point.get('indicator_id') == ioc.id for point in metrics['geo'])
    assert any(asset['name'] == 'controlled-workstation' for asset in metrics['assets'])

    executive_dashboard = client.get('/api/v1/dashboard', headers=executive_auth)
    assert executive_dashboard.status_code == 200
    executive_metrics = executive_dashboard.json()
    assert executive_metrics['active_indicators'] == metrics['active_indicators']
    assert all('indicator_id' not in point and 'event_id' not in point for point in executive_metrics['geo'])
    assert client.get('/api/v1/alerts', headers=executive_auth).status_code == 403
    assert client.get('/api/v1/incidents', headers=executive_auth).status_code == 403

    db.expire_all()
    incident_row = db.get(Incident, incident['id'])
    assert incident_row.state == 'closed' and incident_row.owner_id == responder.id
    assert db.scalar(select(func.count()).select_from(IncidentLink).where(IncidentLink.incident_id == incident['id'])) == 2
    assert db.scalar(select(func.count()).select_from(Timeline).where(Timeline.incident_id == incident['id'])) >= 5
    responder_history = client.get('/api/v1/audit', headers=responder_auth).json()['items']
    assert any(item['action'] == 'incident.updated' for item in responder_history)


def test_incident_list_batches_tlp_label_queries(client, accounts, db):
    """The incident queue must not run two extra queries per incident row."""
    analyst, analyst_auth, _ = accounts['soc_analyst']
    ioc = make_indicator(db, value='203.0.113.40', tlp='red')
    for index in range(120):
        incident = Incident(title=f'CONTROLLED list {index}', owner_id=analyst.id,
                            creator_id=analyst.id, tlp='clear')
        db.add(incident)
        db.flush()
        db.add(IncidentLink(incident_id=incident.id, indicator_id=ioc.id))
        db.add(Timeline(incident_id=incident.id, actor_id=analyst.id, kind='opened',
                        tlp='green', data={'controlled_test': True}))
    db.flush()

    statements = []
    bind = db.get_bind()

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement)

    event.listen(bind, 'before_cursor_execute', before_cursor_execute)
    try:
        response = client.get('/api/v1/incidents', headers=analyst_auth)
    finally:
        event.remove(bind, 'before_cursor_execute', before_cursor_execute)

    assert response.status_code == 200, response.text
    items = response.json()['items']
    assert len(items) == 100
    # Indicator TLP outranks incident and timeline labels.
    assert {item['tlp'] for item in items} == {'red'}
    # incidents + indicator labels + timeline labels + auth/session overhead, not 2N+1.
    assert len(statements) <= 8, len(statements)


def test_integration_event_gateways_are_typed_and_authorized(client, accounts, db):
    admin, admin_auth, _ = accounts['administrator']
    engineer, engineer_auth, _ = accounts['security_engineer']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    value = '203.0.113.30'
    make_indicator(db, value=value)

    for kind in ('siem', 'edr', 'ticketing'):
        result = client.post('/api/v1/integrations/' + kind + '/events', headers=engineer_auth, json={
            'source': 'controlled-' + kind, 'external_id': 'controlled-' + kind + '-1',
            'occurred_at': now().isoformat(), 'asset': 'controlled-asset',
            'observables': [{'type': 'ip', 'value': value}], 'controlled_test': True,
        })
        assert result.status_code == 201, (kind, result.text)
        assert result.json()['replayed'] is False
    db.expire_all()
    sources = set(db.scalars(select(SecurityEvent.source).where(SecurityEvent.external_id.in_(
        ['controlled-siem-1', 'controlled-edr-1', 'controlled-ticketing-1']))).all())
    assert sources == {'siem:controlled-siem', 'edr:controlled-edr', 'ticketing:controlled-ticketing'}

    assert client.post('/api/v1/integrations/unknown/events', headers=admin_auth, json={
        'source': 'x', 'external_id': 'x', 'occurred_at': now().isoformat(), 'asset': 'a',
        'observables': [{'type': 'ip', 'value': value}],
    }).status_code == 404
    assert client.post('/api/v1/integrations/siem/events', headers=analyst_auth, json={
        'source': 'x', 'external_id': 'x', 'occurred_at': now().isoformat(), 'asset': 'a',
        'observables': [{'type': 'ip', 'value': value}],
    }).status_code == 403
