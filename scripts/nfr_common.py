"""Shared measurement helpers for the isolated ThreatLens NFR harnesses.

Nothing in this module talks to the production database or the production search
index.  The caller is responsible for pointing ``DATABASE_URL`` and
``SEARCH_URL`` at isolated targets before importing application modules.
"""
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx


def ensure_port_free(port):
    """Fail fast if a listener already occupies the benchmark port (health checks pass on wrong servers)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))  # any local port, so outbound connections cannot be blocked
        probe.settimeout(1)
        result = probe.connect_ex(('127.0.0.1', port))
        if result == 0:
            raise SystemExit(f'Benchmark port {port} is already in use by another process')


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[position], 2)


def summary(values):
    if not values:
        return {}
    return {'count': len(values), 'p50': percentile(values, .50), 'p95': percentile(values, .95),
            'p99': percentile(values, .99), 'mean': round(statistics.fmean(values), 2),
            'min': round(min(values), 2), 'max': round(max(values), 2)}


def _run(command, timeout=20):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                shell=isinstance(command, str))
        return result.stdout.strip() if result.returncode == 0 else ''
    except Exception:  # noqa: BLE001 - resource sampling must never fail a benchmark
        return ''


def _docker_stats(containers):
    if not containers:
        return []
    lines = _run(['docker', 'stats', '--no-stream', '--format', '{{json .}}', *containers], timeout=25)
    rows = []
    for line in lines.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append({key: payload.get(key) for key in
                     ('Name', 'CPUPerc', 'MemUsage', 'MemPerc', 'NetIO', 'BlockIO', 'PIDs')})
    return rows


def child_pids(pid):
    if not pid:
        return []
    text = _run(['powershell', '-NoProfile', '-Command',
                 f'(Get-CimInstance Win32_Process -Filter "ParentProcessId={int(pid)}").ProcessId'])
    return [int(token) for token in text.split() if token.isdigit()]


def _process_stats(pids):
    rows = []
    for pid in pids or []:
        if not pid:
            continue
        row = {'pid': int(pid)}
        if sys.platform == 'win32':
            text = _run(['powershell', '-NoProfile', '-Command',
                         f"Get-Process -Id {int(pid)} | Select-Object CPU,WorkingSet64 | ConvertTo-Json -Compress"])
            try:
                payload = json.loads(text)
                row['cpu_seconds'] = payload.get('CPU')
                row['working_set_bytes'] = payload.get('WorkingSet64')
            except (json.JSONDecodeError, TypeError, ValueError):
                return rows
        else:
            try:
                with open(f'/proc/{int(pid)}/stat', encoding='utf-8') as handle:
                    fields = handle.read().split()
                with open(f'/proc/{int(pid)}/status', encoding='utf-8') as handle:
                    rss = next((line.split(':')[1].strip() for line in handle if line.startswith('VmRSS:')), None)
                row['cpu_seconds'] = (int(fields[13]) + int(fields[14])) / os.sysconf('SC_CLK_TCK')
                row['working_set_bytes'] = int(rss.split()[0]) * 1024 if rss else None
            except Exception:  # noqa: BLE001
                return rows
        rows.append(row)
    return rows


def resource_sample(containers=None, pids=None, process_pids=None):
    disks = {}
    for letter in ('C:', 'D:', 'E:'):
        try:
            usage = shutil.disk_usage(letter + '\\')
            disks[letter] = {'free_gb': round(usage.free / 1024 ** 3, 2),
                             'used_gb': round(usage.used / 1024 ** 3, 2)}
        except OSError:
            continue
    return {'at': time.time(), 'containers': _docker_stats(containers or []),
            'processes': _process_stats(process_pids if process_pids is not None else pids), 'disks': disks}


class ResourceMonitor(threading.Thread):
    """Sample Docker container and API process-tree resources without blocking load."""

    def __init__(self, containers, pid=None, pids=None, interval=10):
        super().__init__(daemon=True)
        self.containers, self.interval = containers, interval
        self.pids = list(pids if pids is not None else ([pid] if pid else []))
        self.samples, self._stopped = [], threading.Event()

    def run(self):
        while not self._stopped.is_set():
            self.samples.append(resource_sample(self.containers, process_pids=self.pids))
            self._stopped.wait(self.interval)

    def stop(self):
        self._stopped.set()
        if self.is_alive():
            self.join(timeout=max(5, self.interval + 5))

    def summarize(self):
        cpu = []
        memory = []
        for sample in self.samples:
            for row in sample.get('containers', []):
                try:
                    cpu.append(float(str(row.get('CPUPerc', '0')).rstrip('%')))
                except ValueError:
                    pass
            for row in sample.get('processes', []):
                if row.get('working_set_bytes'):
                    memory.append(row['working_set_bytes'])
        return {'samples': len(self.samples), 'interval_seconds': self.interval,
                'sampled_pids': self.pids,
                'container_cpu_percent': summary(cpu), 'api_working_set_bytes': summary(memory),
                'raw': self.samples}


def hardware():
    system = platform.system()
    total_ram = None
    if system == 'Windows':
        text = _run(['powershell', '-NoProfile', '-Command',
                     '(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory'])
        try:
            total_ram = int(text)
        except ValueError:
            total_ram = None
    return {'platform': platform.platform(), 'machine': platform.machine(), 'cpu_count': os.cpu_count(),
            'total_ram_gb': round(total_ram / 1024 ** 3, 2) if total_ram else None,
            'python': sys.version.split()[0], 'docker': _run(['docker', 'version', '--format', '{{.Server.Version}}'])}


def measure_reads(headers, api_url, path, requests_total, concurrency, timeout=60, think_time=0.0):
    """Drive ``requests_total`` real HTTP reads with ``concurrency`` virtual users.

    ``think_time`` (seconds) models a user pausing between requests and spreads
    the initial burst; with 200 users a lock-step burst would exceed the
    database's connection limit and measure pool exhaustion instead of API work.
    """
    limits = httpx.Limits(max_connections=max(20, concurrency * 2),
                          max_keepalive_connections=max(20, concurrency))
    with httpx.Client(limits=limits, timeout=timeout) as client:
        try:
            client.get(api_url + path, headers=headers, timeout=timeout)
        except httpx.HTTPError:
            pass

        per_user, extra = divmod(requests_total, concurrency)

        def user(position):
            rows = []
            if think_time:
                time.sleep(think_time * (position / max(1, concurrency)))
            for index in range(per_user + (1 if position < extra else 0)):
                if think_time and index:
                    time.sleep(think_time)
                started = time.perf_counter()
                try:
                    response = client.get(api_url + path, headers=headers, timeout=timeout)
                    rows.append(((time.perf_counter() - started) * 1000, response.status_code))
                except httpx.HTTPError as exc:
                    rows.append(((time.perf_counter() - started) * 1000, type(exc).__name__))
            return rows

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = [row for rows in pool.map(user, range(concurrency)) for row in rows]
    latencies = [row[0] for row in results]
    codes = {}
    for _, code in results:
        codes[str(code)] = codes.get(str(code), 0) + 1
    return {'requests': requests_total, 'concurrency': concurrency,
            'virtual_users': concurrency, 'think_time_ms': round(think_time * 1000, 1),
            'p50_ms': percentile(latencies, .50), 'p95_ms': percentile(latencies, .95),
            'p99_ms': percentile(latencies, .99), 'mean_ms': round(statistics.fmean(latencies), 2),
            'max_ms': round(max(latencies), 2), 'statuses': codes,
            'failures': sum(count for code, count in codes.items() if not code.startswith('2'))}


SEARCH_MAPPINGS = {'settings': {'number_of_shards': 1, 'number_of_replicas': 0, 'refresh_interval': '-1'},
                   'mappings': {'dynamic': False, 'properties': {
                       'value': {'type': 'text', 'fields': {'keyword': {'type': 'keyword', 'ignore_above': 2048}}},
                       'type': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
                       'status': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
                       'category': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
                       'sources': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
                       'source': {'type': 'text', 'fields': {'keyword': {'type': 'keyword'}}},
                       'id': {'type': 'keyword'}, 'score': {'type': 'integer'},
                       'notes': {'type': 'text'}, 'created_at': {'type': 'date'}}}}


def search_index_stats(base_url, index):
    with httpx.Client(timeout=120) as client:
        count = client.get(f'{base_url}/{index}/_count').json()['count']
        stats = client.get(f'{base_url}/{index}/_stats/store,docs').json()
        store = stats.get('_all', {}).get('primaries', {}).get('store', {}).get('size_in_bytes')
        cluster = client.get(f'{base_url}/_cluster/health').json()
        node = client.get(f'{base_url}/_nodes/stats/jvm').json()
        node_row = next(iter(node.get('nodes', {}).values()), {})
        heap = node_row.get('jvm', {}).get('mem', {}).get('heap_used_in_bytes')
        heap_max = node_row.get('jvm', {}).get('mem', {}).get('heap_max_in_bytes')
    return {'count': count, 'store_bytes': store,
            'store_gb': round(store / 1024 ** 3, 2) if store else None,
            'shards': cluster.get('active_primary_shards'), 'cluster_status': cluster.get('status'),
            'heap_used_bytes': heap, 'heap_max_bytes': heap_max,
            'heap_used_percent': round(heap / heap_max * 100, 1) if heap and heap_max else None}


def build_search_index(base_url, index, documents, batch_size=10000, resume=True):
    """Build (or resume) an isolated synthetic index.  Resuming makes a long
    10M-document load restartable across harness/session interruptions."""
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with httpx.Client(timeout=120) as client:
        head = client.head(f'{base_url}/{index}')
        if head.status_code != 404 and not resume:
            client.delete(f'{base_url}/{index}')
            head = client.head(f'{base_url}/{index}')
        if head.status_code == 404:
            response = client.put(f'{base_url}/{index}', json=SEARCH_MAPPINGS)
            response.raise_for_status()
            start = 0
        else:
            start = client.get(f'{base_url}/{index}/_count').json()['count']
            client.put(f'{base_url}/{index}/_settings', json={'index': {'refresh_interval': '-1'}})
        indexed_now, started = 0, time.perf_counter()
        for begin in range(start, documents, batch_size):
            lines = []
            for i in range(begin, min(begin + batch_size, documents)):
                lines.append(json.dumps({'index': {'_index': index, '_id': f'{index}-{i}'}}))
                lines.append(json.dumps({'id': f'{index}-{i}', 'value': f'bench-{i}.example', 'type': 'domain',
                                         'status': 'active', 'category': 'malware', 'sources': ['bench'],
                                         'source': 'bench', 'score': 50, 'notes': 'benchmark corpus',
                                         'created_at': stamp}))
                indexed_now += 1
            response = client.post(base_url + '/_bulk', content='\n'.join(lines) + '\n',
                                   headers={'Content-Type': 'application/x-ndjson'})
            response.raise_for_status()
            if response.json().get('errors'):
                raise RuntimeError('Benchmark index bulk load reported errors')
        elapsed = time.perf_counter() - started
        client.put(f'{base_url}/{index}/_settings', json={'index': {'refresh_interval': '1s'}})
        client.post(f'{base_url}/{index}/_refresh')
    stats = search_index_stats(base_url, index)
    stats.update({'documents_requested': documents, 'documents_indexed_this_run': indexed_now,
                  'resumed_from': start, 'indexing_seconds': round(elapsed, 2),
                  'indexing_documents_per_second': round(indexed_now / elapsed, 1) if elapsed else None})
    return stats
