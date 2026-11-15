"""Geographic evidence from provider observations and correlated telemetry only."""
from .schemas import GeoObservation


def target_points(events):
    result, seen = [], set()
    for event in events:
        if event.id in seen or not event.details.get('target_geo'):
            continue
        seen.add(event.id)
        try:
            location = GeoObservation.model_validate(event.details['target_geo'])
        except ValueError:
            # Older events may predate boundary validation; never invent coordinates.
            continue
        result.append({**location.model_dump(mode='json'), 'provider': location.source, 'event_id': event.id,
            'asset': event.asset, 'direction': 'target', 'controlled_test': event.controlled_test})
    return result
