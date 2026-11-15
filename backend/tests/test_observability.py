"""NFR-10: structured logs, per-service metrics and health endpoints."""
import json
import logging

from app.observability import JsonFormatter, configure


def test_structured_log_line_is_json_and_redacts_credentials():
    record = logging.LogRecord('threatlens.api', logging.INFO, __file__, 1, 'request handled', (), None)
    record.fields = {'authorization': 'Bearer controlled-token', 'api_key': 'controlled-key',
                     'password': 'controlled-password', 'path': '/api/v1/indicators'}
    line = json.loads(JsonFormatter().format(record))
    assert line['service'] == 'threatlens.api' and line['level'] == 'INFO'
    assert line['message'] == 'request handled'
    assert line['fields']['authorization'] == '[redacted]'
    assert line['fields']['api_key'] == '[redacted]'
    assert line['fields']['password'] == '[redacted]'
    assert line['fields']['path'] == '/api/v1/indicators'


def test_configure_attaches_one_json_handler():
    logger = configure('threatlens.observability-contract')
    logger = configure('threatlens.observability-contract')
    handlers = [handler for handler in logger.handlers if getattr(handler, '_threatlens_json', False)]
    assert len(handlers) == 1


def test_metrics_expose_api_service_and_dependency_gauges(client):
    response = client.get('/metrics')
    assert response.status_code == 200
    body = response.text
    assert 'threatlens_requests_total' in body
    assert 'threatlens_service_heartbeat_timestamp_seconds{service="dispatcher"}' in body
    assert 'threatlens_service_heartbeat_timestamp_seconds{service="scheduler"}' in body
    assert 'threatlens_dependency_up{dependency="postgresql"} 1' in body
    assert 'threatlens_dependency_up{dependency="redis"} 1' in body
    assert 'threatlens_dependency_up{dependency="elasticsearch"} 1' in body
    assert 'threatlens_readiness_up 1' in body


def test_liveness_and_readiness_endpoints(client):
    assert client.get('/health/live').json() == {'status': 'alive'}
    assert client.get('/health/ready').json() == {'status': 'ready'}
