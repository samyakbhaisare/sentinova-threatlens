"""Deterministic, explainable priority score. See docs/ARCHITECTURE.md."""
import math
from datetime import timezone
from decimal import Decimal, ROUND_HALF_UP


def bounded(value):
    if value is None:
        return 0.0
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('Score inputs must be finite')
    return max(0.0, min(100.0, value))


def score(reputation, confidence, last_seen, sightings, at):
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = max(0, (at - last_seen).total_seconds() / 86400)
    inputs = {'reputation': bounded(reputation), 'confidence': bounded(confidence),
              'recency': max(0, 100 * (1 - age / 30)), 'sightings': bounded(max(0, sightings) * 10)}
    weights = {'reputation': .35, 'confidence': .30, 'recency': .20, 'sightings': .15}
    contributions = {key: round(value * weights[key], 6) for key, value in inputs.items()}
    total = int(Decimal(str(sum(contributions.values()))).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
    return total, {'version': 1, 'inputs': inputs, 'weights': weights, 'contributions': contributions}
