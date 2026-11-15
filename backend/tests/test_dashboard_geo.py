"""FR-20/FR-14: the dashboard heatmap is fed by persisted geo evidence only."""
from datetime import timedelta

from app.models import Enrichment, Indicator, SecurityEvent, Sighting, now


def test_dashboard_geo_renders_origin_and_target_points_and_redacts_executive(client, db, accounts):
    stamp = now()
    indicator = Indicator(type='ip', value='9.9.9.9', tlp='clear', status='active', score=80,
                          reputation=87, confidence=90, category='malware',
                          expires_at=stamp + timedelta(days=30), first_seen=stamp, last_seen=stamp)
    db.add(indicator)
    db.flush()
    db.add(Enrichment(indicator_id=indicator.id, provider='ipwhois', expires_at=stamp + timedelta(hours=1), data={
        'provider': 'ipwhois', 'status': 'ok', 'observed_at': stamp.isoformat(),
        'latitude': 37.7749, 'longitude': -122.4194, 'country': 'US',
        'asn': 15169, 'owner': 'Controlled Cloud'}))
    event = SecurityEvent(source='controlled-ipam', external_id='geo-target-1', occurred_at=stamp,
                          asset='controlled-geo-host', observables=[{'type': 'ip', 'value': indicator.value}],
                          controlled_test=True, digest='controlled-geo-digest', details={'target_geo': {
                              'latitude': 52.52, 'longitude': 13.405, 'country': 'DE',
                              'source': 'controlled IPAM telemetry', 'observed_at': stamp.isoformat()}})
    db.add(event)
    db.flush()
    db.add(Sighting(indicator_id=indicator.id, event_id=event.id))
    db.flush()

    response = client.get('/api/v1/dashboard?days=365', headers=accounts['soc_analyst'][1])
    assert response.status_code == 200
    points = response.json()['geo']
    origin = next(point for point in points if point['direction'] == 'origin')
    target = next(point for point in points if point['direction'] == 'target')
    assert origin == {**origin, 'country': 'US', 'indicator_id': indicator.id,
                      'latitude': 37.7749, 'longitude': -122.4194, 'provider': 'ipwhois'}
    assert target == {**target, 'country': 'DE', 'event_id': event.id,
                      'latitude': 52.52, 'longitude': 13.405, 'provider': 'controlled IPAM telemetry'}
    assert target['asset'] == 'controlled-geo-host' and target['controlled_test'] is True

    executive = client.get('/api/v1/dashboard?days=365', headers=accounts['executive'][1])
    assert executive.status_code == 200
    redacted = executive.json()['geo']
    assert redacted and all('indicator_id' not in point and 'event_id' not in point for point in redacted)
    assert {point['country'] for point in redacted} == {'US', 'DE'}
