"""Provider retry contracts. Delays never include response bodies or credentials."""
import math
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


class DeferredRequest(Exception):
    def __init__(self, seconds, reason='provider_backoff'):
        self.seconds = max(1, math.ceil(seconds))
        self.reason = reason
        super().__init__(reason)


def retry_after(value, default=60, at=None):
    if not value:
        return default
    try:
        seconds = float(value)
        if not math.isfinite(seconds):
            return default
    except (ValueError, TypeError):
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                return default
            seconds = (date - (at or datetime.now(timezone.utc))).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return default
    return max(1, math.ceil(seconds))
