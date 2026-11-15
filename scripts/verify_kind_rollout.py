"""NFR-11 Kubernetes (kind) rollout verification.

Runs against the local `sentinova-portability` kind cluster and the
`threatlens` namespace created from `deploy/local-kind`.  It records the
actual object state, probes the API and dashboard through Services with
port-forward, scrapes the readiness/error-budget metric, checks the
cross-service DNS path, and deletes one API pod to measure replacement.

This proves the manifest/image stack runs on a real Kubernetes control plane.
It does not prove a paid cloud cluster/registry rollout, which remains an
operator action.
"""
import json
import os
import re
import secrets
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from nfr_common import ensure_port_free

ROOT = Path(__file__).resolve().parents[1]
RUN = 'nfr11-kind-' + secrets.token_hex(4)
NAMESPACE = os.environ.get('NFR11_NAMESPACE', 'threatlens')
CONTEXT = os.environ.get('NFR11_CONTEXT', 'kind-sentinova-portability')
API_PORT = int(os.environ.get('NFR11_API_PORT', '18080'))
WEB_PORT = int(os.environ.get('NFR11_WEB_PORT', '13080'))


def kubectl(*args, timeout=90):
    command = ['kubectl', '--context', CONTEXT, '-n', NAMESPACE, *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return {'command': ' '.join(command), 'returncode': result.returncode,
            'stdout': result.stdout.strip(), 'stderr': result.stderr.strip()}


def kubectl_json(*args, timeout=90):
    result = kubectl(*args, '-o', 'json', timeout=timeout)
    if result['returncode'] != 0:
        return {'error': result['stderr'], 'command': result['command']}
    return json.loads(result['stdout'])


def wait_port(port, deadline=45):
    until = time.monotonic() + deadline
    while time.monotonic() < until:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def start_port_forward(service, port, target):
    ensure_port_free(port)
    log = (ROOT / 'artifacts' / 'verification' / f'{RUN}-{service}-portforward.log').open('ab')
    process = subprocess.Popen(['kubectl', '--context', CONTEXT, '-n', NAMESPACE, 'port-forward',
                                f'svc/{service}', f'{port}:{target}', '--address', '127.0.0.1'],
                               stdout=log, stderr=log)
    if not wait_port(port):
        process.terminate()
        raise RuntimeError(f'port-forward for {service} did not become ready')
    return process


def probe(base, path):
    started = time.perf_counter()
    try:
        response = httpx.get(base + path, timeout=10)
        return {'path': path, 'status': response.status_code,
                'latency_ms': round((time.perf_counter() - started) * 1000, 2)}
    except httpx.HTTPError as exc:
        return {'path': path, 'status': type(exc).__name__,
                'latency_ms': round((time.perf_counter() - started) * 1000, 2)}


def summarize_deployments():
    payload = kubectl_json('get', 'deployments')
    return {item['metadata']['name']: {
        'desired': item.get('spec', {}).get('replicas'),
        'ready': item.get('status', {}).get('readyReplicas', 0),
        'available': item.get('status', {}).get('availableReplicas', 0),
        'updated': item.get('status', {}).get('updatedReplicas', 0),
        'image': item['spec']['template']['spec']['containers'][0]['image'],
    } for item in payload.get('items', [])}


def summarize_pods():
    payload = kubectl_json('get', 'pods')
    rows = []
    for item in payload.get('items', []):
        statuses = item.get('status', {}).get('containerStatuses') or []
        rows.append({
            'name': item['metadata']['name'],
            'phase': item.get('status', {}).get('phase'),
            'node': item.get('spec', {}).get('nodeName'),
            'image': statuses[0].get('image') if statuses else None,
            'image_id': statuses[0].get('imageID') if statuses else None,
            'ready': all(state.get('ready') for state in statuses) if statuses else False,
            'restarts': sum(state.get('restartCount', 0) for state in statuses),
        })
    return rows


def metrics_gauges(text):
    patterns = {
        'readiness': r'^threatlens_readiness_up ([0-9.]+)$',
        'postgresql': r'^threatlens_dependency_up\{dependency="postgresql"\} ([0-9.]+)$',
        'redis': r'^threatlens_dependency_up\{dependency="redis"\} ([0-9.]+)$',
        'elasticsearch': r'^threatlens_dependency_up\{dependency="elasticsearch"\} ([0-9.]+)$',
    }
    return {name: (float(match.group(1)) if (match := re.search(pattern, text, re.MULTILINE)) else None)
            for name, pattern in patterns.items()}


def main():
    report = {'run': RUN, 'measured_at': datetime.now(timezone.utc).isoformat(),
              'namespace': NAMESPACE, 'context': CONTEXT,
              'requirement': 'NFR-11: entire stack runs from docker-compose up locally and on Kubernetes in cloud',
              'scope': 'real single-node kind control plane; local managed-equivalent data services; not a paid cloud cluster'}
    api_forward = web_forward = None
    try:
        report['cluster'] = kubectl_json('get', 'nodes').get('items', [])
        report['cluster'] = [{'name': n['metadata']['name'],
                              'ready': any(c.get('type') == 'Ready' and c.get('status') == 'True'
                                           for c in n.get('status', {}).get('conditions', [])),
                              'version': n.get('status', {}).get('nodeInfo', {}).get('kubeletVersion'),
                              'runtime': n.get('status', {}).get('nodeInfo', {}).get('containerRuntimeVersion')}
                             for n in report['cluster']]
        report['deployments_before'] = summarize_deployments()
        report['pods_before'] = summarize_pods()
        report['services'] = [{'name': i['metadata']['name'], 'type': i.get('spec', {}).get('type', 'ClusterIP'),
                               'ports': i.get('spec', {}).get('ports')}
                              for i in kubectl_json('get', 'services').get('items', [])]
        report['pvc'] = [{'name': i['metadata']['name'], 'phase': i.get('status', {}).get('phase'),
                          'capacity': i.get('status', {}).get('capacity'),
                          'access_modes': i.get('status', {}).get('accessModes'),
                          'storage_class': i.get('spec', {}).get('storageClassName')}
                         for i in kubectl_json('get', 'pvc').get('items', [])]
        report['policy'] = {
            'networkpolicies': [i['metadata']['name'] for i in kubectl_json('get', 'networkpolicies').get('items', [])],
            'poddisruptionbudgets': [i['metadata']['name'] for i in kubectl_json('get', 'poddisruptionbudgets').get('items', [])],
            'ingresses': [i['metadata']['name'] for i in kubectl_json('get', 'ingresses').get('items', [])],
            'horizontalpodautoscalers': [i['metadata']['name'] for i in kubectl_json('get', 'horizontalpodautoscalers').get('items', [])],
        }
        report['rollout_status'] = kubectl('rollout', 'status', 'deployment/api', '--timeout=120s')['stdout']

        report['dns_from_frontend'] = kubectl(
            'exec', 'deploy/frontend', '--', 'wget', '-qO-', 'http://api:8000/health/live')['stdout']

        api_forward = start_port_forward('api', API_PORT, 8000)
        web_forward = start_port_forward('frontend', WEB_PORT, 3000)
        report['api_probes'] = [probe(f'http://127.0.0.1:{API_PORT}', path)
                                for path in ('/health/live', '/health/ready')]
        metrics = httpx.get(f'http://127.0.0.1:{API_PORT}/metrics', timeout=15).text
        report['metrics'] = metrics_gauges(metrics)
        report['dashboard_probes'] = [probe(f'http://127.0.0.1:{WEB_PORT}', path)
                                      for path in ('/healthz', '/metrics', '/')]
        report['dashboard_healthz_body'] = httpx.get(
            f'http://127.0.0.1:{WEB_PORT}/healthz', timeout=10).text[:200]

        # Self-healing: delete one API pod and wait for a replacement to become Ready.
        before = [p for p in summarize_pods() if p['name'].startswith('api-')]
        victim = before[0]['name']
        started = time.perf_counter()
        deleted = kubectl('delete', 'pod', victim, '--wait=false')
        replacement = None
        deadline = time.perf_counter() + 120
        while time.perf_counter() < deadline:
            pods = [p for p in summarize_pods() if p['name'].startswith('api-')]
            ready = [p for p in pods if p['ready'] and p['name'] != victim]
            if len(ready) >= 2:
                replacement = {'deleted_pod': victim, 'delete_command': deleted,
                               'remaining_ready': [p['name'] for p in ready],
                               'recovery_seconds': round(time.perf_counter() - started, 2)}
                break
            time.sleep(2)
        report['self_healing'] = replacement or {'deleted_pod': victim, 'timed_out': True,
                                                 'elapsed_seconds': round(time.perf_counter() - started, 2)}
        report['deployments_after'] = summarize_deployments()
        report['pods_after'] = summarize_pods()

        report['api_log_tail'] = kubectl('logs', 'deploy/api', '--tail=40')['stdout']
        report['api_log_errors'] = [line for line in report['api_log_tail'].splitlines()
                                    if re.search(r'\b(ERROR|Traceback|CRITICAL)\b', line)]
        report['warnings'] = [f'hpa_metrics_unavailable: {line}' for line in
                              kubectl('get', 'events', '--field-selector', 'reason=FailedGetResourceMetric')['stdout'].splitlines()
                              if line.strip()][:5]
    finally:
        for process in (api_forward, web_forward):
            if process and process.poll() is None:
                process.terminate()

    output = ROOT / 'artifacts' / 'verification' / f'{RUN}.json'
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: report[key] for key in
                      ('run', 'cluster', 'deployments_before', 'pvc', 'api_probes', 'metrics',
                       'dashboard_probes', 'dns_from_frontend', 'self_healing')}, indent=2))
    print('saved', output)


if __name__ == '__main__':
    main()
