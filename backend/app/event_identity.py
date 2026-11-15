"""Semantic replay compatibility across additive event-schema migrations."""
from datetime import timezone


def equivalent(stored, incoming):
    timestamp = stored.occurred_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    if timestamp.astimezone(timezone.utc) != incoming.occurred_at.astimezone(timezone.utc):
        return False
    if 'tlp' in incoming.model_fields_set and stored.tlp != incoming.tlp:
        return False
    return (stored.source == incoming.source and stored.external_id == incoming.external_id
            and stored.asset == incoming.asset and stored.details == incoming.details
            and stored.controlled_test == incoming.controlled_test
            and stored.observables == [observable.model_dump() for observable in incoming.observables])
