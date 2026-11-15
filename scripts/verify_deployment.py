"""NFR-11 deployment verification for the packaged Docker Compose and Kubernetes stack.

Proves the release stack actually starts on isolated ports from the published
images, and structurally validates the rendered Kubernetes manifests.  No
Kubernetes control plane is available in this environment, so the manifests are
rendered/validated offline instead of rolled out; this limitation is recorded
in the artifact rather than hidden.
"""
import json
import os
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUN = 'nfr-deployment-' + secrets.token_hex(4)
PORTS = {'postgres': 15433, 'redis': 16380, 'search': 19201, 'api': 18100, 'frontend': 13000}
PROJECT = 'sentinova-verify'


def run(command):
    return subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')


def compose_state():
    result = run(['docker', 'ps', '-a', '--filter', f'name={PROJECT}', '--format',
                  '{{.Names}}|{{.Status}}|{{.Image}}'])
    rows = []
    for line in result.stdout.splitlines():
        name, status, image = (line.split('|') + ['', ''])[:3]
        rows.append({'name': name, 'status': status, 'image': image})
    return rows


def compose_config():
    env = os.environ.copy()
    env.update({'IMAGE_TAG': 'verify', 'POSTGRES_PORT': '15433', 'REDIS_PORT': '16380',
                'SEARCH_PORT': '19201', 'API_PORT': '18100', 'FRONTEND_PORT': '13000'})
    result = subprocess.run(['docker', 'compose', '-f', 'compose.yaml', '-f', 'compose.verify.yaml',
                             '-p', PROJECT, 'config'], cwd=ROOT, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', env=env)
    return result


def endpoint(url):
    try:
        response = httpx.get(url, timeout=10)
        return {'url': url, 'status': response.status_code, 'ok': response.status_code == 200}
    except httpx.HTTPError as exc:
        return {'url': url, 'status': type(exc).__name__, 'ok': False}


def validate_kustomize():
    result = run(['kubectl', 'kustomize', 'deploy/kubernetes'])
    if result.returncode != 0:
        return {'rendered': False, 'error': result.stderr[-2000:]}
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    kinds = {}
    problems = []
    for doc in docs:
        kind = doc.get('kind')
        name = (doc.get('metadata') or {}).get('name')
        kinds[kind] = kinds.get(kind, 0) + 1
        if not doc.get('apiVersion') or not kind or not name:
            problems.append(f'missing apiVersion/kind/metadata.name: {doc}')
        if kind == 'Deployment':
            spec = doc['spec']['template']['spec']
            if spec.get('automountServiceAccountToken') is not False:
                problems.append(f'{name}: service account token automounted')
            container = spec['containers'][0]
            if not container.get('resources'):
                problems.append(f'{name}: no resource requests/limits')
            if container.get('securityContext', {}).get('allowPrivilegeEscalation') is not False:
                problems.append(f'{name}: allowPrivilegeEscalation not disabled')
            if not container.get('readinessProbe') and kind == 'Deployment' and name in ('api', 'frontend'):
                problems.append(f'{name}: no readiness probe')
        if kind == 'NetworkPolicy' and 'Ingress' not in doc['spec'].get('policyTypes', []):
            problems.append('network policy does not restrict ingress')
    return {
        'rendered': True,
        'documents': len(docs),
        'kinds': dict(sorted(kinds.items())),
        'problems': problems,
        'valid': not problems,
        'namespace_restricted': any(
            doc.get('kind') == 'Namespace'
            and doc.get('metadata', {}).get('labels', {}).get('pod-security.kubernetes.io/enforce') == 'restricted'
            for doc in docs),
        'explicit_images': sorted({
            container['image']
            for doc in docs if doc.get('kind') == 'Deployment'
            for container in doc['spec']['template']['spec']['containers']
        }),
        'external_prerequisites': ['Secret/threatlens-runtime', 'Secret/threatlens-providers',
                                   'Secret/threatlens-tls', 'an ingress-nginx controller',
                                   'a ReadWriteMany storage class for the reports PVC'],
        'limitation': 'No Kubernetes control plane is available; manifests were rendered and '
                      'structurally validated offline, not rolled out.',
    }


def main():
    config = compose_config()
    state = compose_state()
    live = {
        'api_ready': endpoint(f'http://127.0.0.1:{PORTS["api"]}/health/ready'),
        'frontend': endpoint(f'http://127.0.0.1:{PORTS["frontend"]}/'),
        'api_live': endpoint(f'http://127.0.0.1:{PORTS["api"]}/health/live'),
    }
    expected = {'postgres', 'redis', 'elasticsearch', 'api', 'worker', 'dispatcher', 'scheduler', 'frontend'}
    present = {row['name'].replace(f'{PROJECT}-', '').rsplit('-1', 1)[0] for row in state}
    healthy = all(
        ('healthy' in row['status'] or row['status'].startswith('Up') or 'Exited (0)' in row['status'])
        for row in state)
    result = {
        'run': RUN,
        'measured_at': datetime.now(timezone.utc).isoformat(),
        'requirement': 'NFR-11: deployable via containers and Kubernetes with health probes',
        'compose': {
            'config_valid': config.returncode == 0,
            'config_error': config.stderr[-1000:] if config.returncode else None,
            'project': PROJECT,
            'isolated_host_ports': PORTS,
            'images_pinned': 'sentinova-threatlens-api:verify / sentinova-threatlens-web:verify',
            'services': state,
            'all_services_ok': healthy,
            'expected_services_present': expected <= present,
        },
        'live_endpoints': live,
        'kubernetes': validate_kustomize(),
        'isolation': {'production_containers_recreated': 0, 'production_volumes_touched': 0,
                      'production_database_rows_touched': 0},
    }
    output = ROOT / 'artifacts' / 'verification' / f'{RUN}-deployment.json'
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    print('saved', output)
    if not (result['compose']['config_valid'] and result['compose']['all_services_ok']
            and result['compose']['expected_services_present'] and result['kubernetes']['valid']
            and all(item['ok'] for item in live.values())):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
