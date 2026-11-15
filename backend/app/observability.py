"""Structured JSON logging shared by the API, workers and scheduler (NFR-10).

Every service writes one JSON object per log line with a timestamp, level,
service/logger and message.  Sensitive keys are redacted before serialisation so
credentials and tokens can never leak through logs (PRD 13.5).
"""
import json
import logging
from datetime import datetime, timezone

SENSITIVE = ('authorization', 'password', 'secret', 'token', 'api_key', 'apikey', 'x-apikey')


def _redact(value):
    if isinstance(value, dict):
        return {key: ('[redacted]' if any(marker in str(key).lower() for marker in SENSITIVE) else _redact(item))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            'level': record.levelname,
            'service': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        if record.stack_info:
            payload['stack'] = self.formatStack(record.stack_info)
        if getattr(record, 'fields', None):
            payload['fields'] = _redact(record.fields)
        return json.dumps(payload, default=str, separators=(',', ':'))


def configure(service):
    """Attach one JSON handler to the service's logger tree without duplicates."""
    logger = logging.getLogger(service)
    if not any(getattr(handler, '_threatlens_json', False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._threatlens_json = True
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
