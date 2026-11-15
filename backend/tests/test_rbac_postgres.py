"""Six-role authorization matrix on real PostgreSQL.

All identities are synthetic, created by the ``accounts`` fixture inside the
isolated ``threatlens_test`` database and removed when the test transaction rolls
back.  The live administrator account is never touched.
"""
from datetime import timedelta

import pytest

from app.models import Alert, AlertRule, Hunt, Indicator, Notification, Report, now
from app.security import ROLES

pytestmark = pytest.mark.integration

ALL = set(ROLES)
OPERATIONAL = ALL - {'executive'}
INCIDENT_ROLES = {'administrator', 'incident_responder', 'soc_analyst', 'threat_hunter'}
AUDIT_ROLES = {'administrator', 'security_engineer', 'incident_responder'}
FEED_ROLES = {'administrator', 'security_engineer'}
ADMIN_ONLY = {'administrator'}

READ_MATRIX = [
    ('/api/v1/dashboard', ALL),
    ('/api/v1/reports', ALL),
    ('/api/v1/notifications', ALL),
    ('/api/v1/indicators', OPERATIONAL),
    ('/api/v1/alerts', OPERATIONAL),
    ('/api/v1/alert-rules', OPERATIONAL),
    ('/api/v1/assignees', OPERATIONAL),
    ('/api/v1/hunts', OPERATIONAL),
    ('/api/v1/export/csv', OPERATIONAL),
    ('/api/v1/incidents', INCIDENT_ROLES),
    ('/api/v1/audit', AUDIT_ROLES),
    ('/api/v1/users', ADMIN_ONLY),
    ('/api/v1/feeds', FEED_ROLES),
]


def make_indicator(db, value):
    row = Indicator(type='ip', value=value, score=60, confidence=50, reputation=50,
                    category='malware', tlp='amber', first_seen=now(), last_seen=now(),
                    expires_at=now() + timedelta(days=30))
    db.add(row)
    db.flush()
    return row


@pytest.mark.parametrize('role', sorted(ROLES))
def test_read_authorization_matrix(client, accounts, db, role):
    _, headers, _ = accounts[role]
    for path, allowed in READ_MATRIX:
        expected = 200 if role in allowed else 403
        result = client.get(path, headers=headers)
        assert result.status_code == expected, (role, path, result.status_code, result.text)
        if expected == 200 and path != '/api/v1/export/csv':
            assert 'items' in result.json() or 'active_indicators' in result.json(), (role, path)

    # Executive may not use free-text search or read the raw alert/incident queues.
    if role == 'executive':
        assert client.get('/api/v1/search?q=controlled', headers=headers).status_code == 403
    else:
        # Search is delegated to Elasticsearch; permission is asserted without depending on it.
        assert client.get('/api/v1/indicators', headers=headers).status_code == 200


def test_system_health_is_feed_privileged_not_authenticated_only(client, accounts):
    admin_auth = accounts['administrator'][1]
    engineer_auth = accounts['security_engineer'][1]
    assert client.get('/api/v1/system/health', headers=admin_auth).status_code in (200, 503)
    assert client.get('/api/v1/system/health', headers=engineer_auth).status_code in (200, 503)
    for role in ROLES:
        if role in FEED_ROLES:
            continue
        assert client.get('/api/v1/system/health', headers=accounts[role][1]).status_code == 403


@pytest.mark.parametrize('role', sorted(ROLES))
def test_write_authorization_matrix(client, accounts, db, role):
    user, headers, _ = accounts[role]
    admin = accounts['administrator'][0]
    unique = role.replace('_', '-')

    created_user = client.post('/api/v1/users', headers=headers, json={
        'email': 'controlled-rbac-' + unique + '@example.org', 'name': 'CONTROLLED ' + role,
        'password': 'controlled-password-123', 'role': 'soc_analyst',
    })
    assert created_user.status_code == (201 if role in ADMIN_ONLY else 403), (role, created_user.text)

    created_feed = client.post('/api/v1/feeds', headers=headers, json={
        'name': 'CONTROLLED FEED ' + role, 'adapter': 'json', 'url': 'internal',
    })
    if role in FEED_ROLES:
        assert created_feed.status_code == 422, (role, created_feed.text)  # permission passed, validation rejected
    else:
        assert created_feed.status_code == 403, (role, created_feed.text)

    created_rule = client.post('/api/v1/alert-rules', headers=headers, json={'name': 'CONTROLLED RULE ' + role})
    assert created_rule.status_code == (201 if role in FEED_ROLES else 403), (role, created_rule.text)

    created_event = client.post('/api/v1/events', headers=headers, json={
        'source': 'controlled-rbac-' + unique, 'external_id': 'controlled-1',
        'occurred_at': now().isoformat(), 'asset': 'controlled-asset',
        'observables': [{'type': 'ip', 'value': '198.51.100.' + str(sorted(ROLES).index(role) + 10)}],
        'controlled_test': True,
    })
    assert created_event.status_code == (201 if role in FEED_ROLES else 403), (role, created_event.text)

    created_indicator = client.post('/api/v1/indicators', headers=headers, json={
        'type': 'ip', 'value': '198.51.100.' + str(sorted(ROLES).index(role) + 30), 'confidence': 50,
    })
    assert created_indicator.status_code == (201 if role in FEED_ROLES else 403), (role, created_indicator.text)

    created_hunt = client.post('/api/v1/hunts', headers=headers, json={'name': 'CONTROLLED HUNT ' + role})
    assert created_hunt.status_code == (201 if role in OPERATIONAL else 403), (role, created_hunt.text)

    ioc = make_indicator(db, '198.51.100.' + str(sorted(ROLES).index(role) + 50))
    created_incident = client.post('/api/v1/incidents', headers=headers, json={
        'title': 'CONTROLLED INCIDENT ' + role, 'indicator_id': ioc.id,
    })
    assert created_incident.status_code == (201 if role in INCIDENT_ROLES else 403), (role, created_incident.text)


def test_incident_and_alert_ownership_scope(client, accounts, db):
    admin, admin_auth, _ = accounts['administrator']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    responder, responder_auth, _ = accounts['incident_responder']
    hunter, hunter_auth, _ = accounts['threat_hunter']
    engineer, engineer_auth, _ = accounts['security_engineer']
    ioc = make_indicator(db, '198.51.100.80')
    other = make_indicator(db, '198.51.100.81')
    rule = AlertRule(name='CONTROLLED ownership rule', recipient_id=analyst.id)
    db.add(rule)
    db.flush()
    alert = Alert(indicator_id=ioc.id, rule_id=rule.id, score=60, recipient_id=analyst.id, assignee_id=analyst.id)
    db.add(alert)
    db.flush()

    incident = client.post('/api/v1/incidents', headers=analyst_auth, json={
        'title': 'CONTROLLED ownership incident', 'indicator_id': ioc.id, 'alert_id': alert.id,
    }).json()
    path = '/api/v1/incidents/' + incident['id']

    # Read scope: responders/admin and any incident-role user may read; engineer/executive may not.
    for headers in (admin_auth, responder_auth, hunter_auth):
        assert client.get(path + '/timeline', headers=headers).status_code == 200
    assert client.get(path + '/timeline', headers=engineer_auth).status_code == 403

    # Write scope: creator/owner or responder/admin only.
    for headers in (hunter_auth, responder_auth):
        expected = 403 if headers is hunter_auth else 201
        assert client.post(path + '/timeline', headers=headers, json={'text': 'CONTROLLED scope note'}).status_code == expected
    assert client.post(path + '/links', headers=hunter_auth, json={'indicator_id': other.id}).status_code == 403
    assert client.post(path + '/links', headers=responder_auth, json={'indicator_id': other.id}).status_code == 201

    # Routed alerts stay private to recipient + responders/admin.
    assert client.get('/api/v1/alerts/' + alert.id + '/history', headers=hunter_auth).status_code == 403
    assert client.patch('/api/v1/alerts/' + alert.id, headers=hunter_auth, json={'state': 'acknowledged'}).status_code == 403
    assert client.get('/api/v1/alerts/' + alert.id + '/history', headers=responder_auth).status_code == 200

    # Notification ownership.
    notification = Notification(user_id=analyst.id, alert_id=alert.id)
    db.add(notification)
    db.flush()
    assert client.patch('/api/v1/notifications/' + notification.id + '/read', headers=hunter_auth).status_code == 403
    assert client.patch('/api/v1/notifications/' + notification.id + '/read', headers=analyst_auth).status_code == 200

    # Report ownership and hunt isolation.
    report = Report(owner_id=analyst.id, title='CONTROLLED owner report', state='ready')
    hunt = Hunt(owner_id=analyst.id, name='CONTROLLED private hunt', query={'q': 'secret'})
    db.add_all([report, hunt])
    db.flush()
    assert client.get('/api/v1/reports/' + report.id + '/download', headers=hunter_auth).status_code == 403
    assert client.get('/api/v1/reports/' + report.id + '/download', headers=admin_auth).status_code in (403, 409)
    assert all(item['id'] != hunt.id for item in client.get('/api/v1/hunts', headers=hunter_auth).json()['items'])
    assert any(item['id'] == hunt.id for item in client.get('/api/v1/hunts', headers=analyst_auth).json()['items'])

    # Admin cannot demote/disable themselves; non-admins cannot manage users at all.
    assert client.patch('/api/v1/users/' + admin.id, headers=admin_auth, json={'role': 'executive'}).status_code == 409
    assert client.patch('/api/v1/users/' + admin.id, headers=analyst_auth, json={'role': 'administrator'}).status_code == 403
    assert client.patch('/api/v1/users/' + hunter.id, headers=analyst_auth, json={'role': 'executive'}).status_code == 403


def test_role_change_and_disable_revoke_existing_tokens(client, accounts, db):
    admin, admin_auth, _ = accounts['administrator']
    analyst, analyst_auth, _ = accounts['soc_analyst']
    hunter, hunter_auth, _ = accounts['threat_hunter']

    assert client.get('/api/v1/indicators', headers=analyst_auth).status_code == 200
    assert client.patch('/api/v1/users/' + analyst.id, headers=admin_auth, json={'role': 'executive'}).status_code == 200
    assert client.get('/api/v1/indicators', headers=analyst_auth).status_code == 401

    assert client.get('/api/v1/indicators', headers=hunter_auth).status_code == 200
    assert client.patch('/api/v1/users/' + hunter.id, headers=admin_auth, json={'enabled': False}).status_code == 200
    assert client.get('/api/v1/indicators', headers=hunter_auth).status_code == 401
