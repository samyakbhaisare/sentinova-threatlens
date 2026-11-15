import redis
from fastapi.testclient import TestClient

from app.main import app, config


def test_anonymous_api_and_health_contract_without_backing_services():
    with TestClient(app) as client:
        response=client.get('/api/v1/auth/me')
        assert response.status_code==401
        assert response.json()['error_code']=='http_401'
        assert response.json()['correlation_id']
        assert response.headers['x-content-type-options']=='nosniff'
        assert client.get('/health/live').json()=={'status':'alive'}


def test_unavailable_rate_limiter_fails_closed_with_uniform_error(monkeypatch):
    monkeypatch.setattr(config,'test_mode',False)
    def unavailable(*args,**kwargs):
        assert kwargs['socket_connect_timeout']==2
        assert kwargs['socket_timeout']==2
        raise redis.ConnectionError('controlled dependency outage')
    monkeypatch.setattr('app.main.aioredis.from_url',unavailable)
    with TestClient(app) as client:
        response=client.get('/api/v1/auth/me')
        assert response.status_code==503
        assert response.json()['error_code']=='dependency_unavailable'
        assert 'controlled dependency outage' not in response.text
