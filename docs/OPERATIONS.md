# Operational runbook

## Current implementation notes
New schema changes require an authorized application-owner migration to the current head (`0005`). Existing evidence and data must be retained; do not rewrite history or backfill measurements.

ATT&CK synchronization is queued through `/api/v1/attack/sync` and scheduled weekly; it fetches the fixed official enterprise STIX URL, validates before mutation, preserves lifecycle metadata and records checksum/count or failure. Unknown analyst technique IDs remain explicitly unresolved until source validation. The attempted real transfer timed out; no successful live sync is claimed.

The scheduler captures at most one measured risk snapshot per UTC hour. Do not synthesize missing periods or backfill historical posture from current data. The real-PostgreSQL suite exercises the append-only triggers and grants; production lock-contention behaviour remains a deployment gate.

Bulk exports run on the operations queue with 500-row pages and ten-minute leases. Old queued jobs and expired leases are redispatched; claims are atomic and attempts capped at three. Inspect job status, cap flag, manifest/digest and current classification before treating an output as usable. Cancelled/failed attempt files are private and retained; implement reviewed retention cleanup before large production use.

Legacy unclassified narrative is conservatively migrated red. Ordinary edits cannot lower labels; unmanifested PDFs require regeneration. Source share locks during download and exclusive worker locks during external enrichment protect classification boundaries, but PostgreSQL contention/stream lifetime must be verified in the real environment.

## Environment recovery boundary
When Docker fails with configuration/I/O errors, stop treating readiness failures as application regression evidence. Preserve containers, volumes, credentials and project files. Do not factory-reset, prune or delete data. The host owner must repair capacity/daemon configuration using their own recovery procedure. Resume migrations and service checks only after infrastructure recovery.

## Initialization and access
Create the first administrator using the interactive CLI; no default password is shipped. Create employees with least-privilege roles and distribute initial/reset credentials privately. Review role assignment and disabled accounts monthly. Rotate JWT/AES keys with a reviewed migration plan: changing AES keys without re-encryption loses access to TOTP secrets.

## Feed operations
Read the **Feed sources and data-use evidence** section below. Configure public sources using `python -m app.cli configure-feeds`; provider keys are separate mounted files. Feed UI shows accepted/rejected counts and independent timestamps. Missing credentials, HTTP failures or malformed transport must remain visible. Re-poll is idempotent by canonical type/value. A partial poll may commit safe batches; retry preserves provenance.

If a source stalls: examine sanitized error type and service/provider availability, review provider quota/terms, disable it while investigating, then re-enable/re-poll. Do not browse returned malicious URLs. Catalog feeds are independent organizations, though aggregated feeds may overlap.

## Monitoring
`/health/live` checks API process; `/health/ready` checks DB/Redis/search. Engineer `/api/v1/system/health` shows dispatcher/scheduler heartbeats and pending outbox count. `/metrics` exposes API request counts/latency, per-dependency gauges, `threatlens_readiness_up` and outbox depth. Prometheus recording/alerting rules for the NFR-04 SLO are in `deploy/prometheus/threatlens-slo-rules.yaml`, the runbook is the **Availability SLO (NFR-04)** section below, and `scripts/availability_monitor.py` records the real 30-day window. Central Prometheus/Grafana deployment and alert routing remain operator integration.

Growing outbox: verify maintenance worker, search write permission/disk watermarks, Redis availability. Records are retained for replay. Elasticsearch is rebuildable from PostgreSQL; no tool should declare success merely because Redis publication succeeded. Persistent notification records support reconnect; realtime transport itself is not durable.

Index projection must succeed before invalidation publication. API and workers must use the same `SEARCH_INDEX`; pub/sub uses `<index>:events` so test instances do not share production fanout. Reproject pre-existing security events to populate `details_text` when rebuilding the search index; no production reprojection has been executed in this environment. New eligible IOCs queue enrichment; rate-limited/transient provider results remain explicitly deferred. Geolocation requires `GEOLOCATION_ENABLED=true` after entitlement review.

## Backup and recovery policy
- Daily encrypted PostgreSQL logical backup and continuous WAL/PITR where available; daily report-volume snapshot.
- Retain audit backups at least 400 days on immutable/off-system storage; restrict deletion to a separately reviewed retention role. Runtime has no evidence deletion permission.
- Back up secret-manager key versions securely; do not include secrets in the submission archive.
- Quarterly restore into an isolated environment, apply grants, check row counts and run `python -m app.cli verify-audit`; verify reports and reindex. An encrypted restore drill passed on 2026-11-09 (10/10 table counts, grants and append-only triggers preserved); the quarterly production cadence remains an operating policy.
- Avoid destructive Alembic downgrades; the initial migration explicitly rejects downgrade.

## Native processes
`artifacts/processes.json` records only processes started by `scripts/start_local.py`. Logs are per service in `artifacts/`. Do not kill processes based only on a port number. The Compose API is published on host port 8100 by default; adjust the port variables if your host differs. Use project-local TEMP/TMP paths when the system drive is constrained.

## Feed sources and data-use evidence

Reviewed 2026-10-17. Sources are processed only as data; ThreatLens never visits an IOC URL or executes a payload.

| Source | Endpoint selection | Schedule | Policy/source evidence |
|---|---|---|---|
| CISA KEV | Official JSON catalog | 6h | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Feodo Tracker | Recommended C2 JSON list | 1h | https://feodotracker.abuse.ch/blocklist/ |
| Blocklist.de | FTP-service attacker IP export | 1h | https://www.blocklist.de/en/export.html explicitly publishes per-service downloads, refreshed every 30 minutes |
| Emerging Threats | Public compromised IP export | 24h | https://rules.emergingthreats.net/blockrules/ |
| CINS Army | Public community IP subset | 24h | https://cinsscore.com/ expressly permits parsing/using the provided text file |
| IPsum | Published level-8 IP subset | 24h | https://github.com/stamparm/ipsum — Unlicense; upstream aggregated evidence is not six independent confirmations |

IPsum's level-8 file is an explicitly published filtered feed, not an arbitrary truncation. Source reliability values in the catalog are installation policy inputs (50–90), not provider-issued confidence. Missing record confidence is zero. CISA explicitly confirms exploitation and receives confidence 100. Raw provider scales are never fabricated.

OpenPhish was initially probed and failed with HTTPStatusError. Its current https://openphish.com/terms.html forbids organizational security operations without written consent. It has been removed from the default catalog and allowlist. Phishing Army was reviewed but not selected because its upstream licensing obligations may include restricted providers.

Real VirusTotal and AbuseIPDB enrichment connectors require operator-mounted credentials and usage rights. VirusTotal public API and free geolocation tiers must be checked for the intended commercial deployment before activation. TAXII requires an operator allowlisted endpoint and a secret reference. OTX and abuse.ch adapters are implemented but not counted toward the operating-source target without credentials and a successful run.

The first live parser probe succeeded for CISA (1,748), Feodo (1), Emerging Threats (497), CINS (15,000), and the full IPsum list (122,301). These are observed probe counts, not database ingestion or scheduling evidence. Subsequent selected-catalog probes and operational status are recorded separately.

## Availability SLO (NFR-04)

**PRD criterion (v1.0, §NFR-04):** “Availability — Target 99.5% monthly
availability for the core API and dashboard.”

The PRD does not define a shorter acceptance window. A monthly target can only
be accepted from a real elapsed month of samples; a load test or fault drill is
supporting evidence, never a substitute for the elapsed window. This section
defines the measurement, the alerting and the recovery procedure so the target
can be observed and audited, and records what has actually been measured so far.

### 1. Definition

| Term | Definition |
| --- | --- |
| Availability | Fraction of probe cycles in the trailing 30 days where the core API **and** dashboard were both healthy |
| Healthy API cycle | `GET /health/live` = 200 **and** `GET /health/ready` = 200 |
| Healthy dashboard cycle | `GET /healthz` = 200 **and** `GET /` = 200 |
| Target | 99.5% per 30-day window |
| Allowed downtime | 216 minutes per 30-day month (0.5% × 43,200 min) |
| Error budget | 216 minutes; spent by any cycle where either surface is unhealthy |

`/health/ready` is 200 only when PostgreSQL, Redis and Elasticsearch all
respond, so a dependency outage counts as unavailability of the core API. The
dashboard `/healthz` route is provided by the Next.js frontend; `/` proves the
rendered application is being served.

### 2. Probe sources

1. **Application metric (primary, for Prometheus).** `/metrics` exposes
   `threatlens_readiness_up` (1 = every dependency healthy, 0 = at least one
   failing), alongside `threatlens_dependency_up{dependency}` and
   `threatlens_requests_total{method,status}`. Shipping these to a 30-day
   Prometheus retention is the production measurement.
2. **Independent black-box monitor.** `scripts/availability_monitor.py` probes
   the same four endpoints over HTTP and appends one JSON record per cycle to a
   JSONL file. It computes the trailing 30-day ratio and refuses to call a
   partial window complete.

Neither source fabricates history. A fresh state file reports
`window_complete: false`.

### 3. Prometheus rules

`deploy/prometheus/threatlens-slo-rules.yaml` defines:

- `threatlens:availability:ratio_30d` — `avg_over_time(threatlens_readiness_up[30d])`.
- `threatlens:error_budget:remaining_ratio_30d` — 1 = full budget, 0 = spent.
- `threatlens:http_5xx:ratio_5m` — API error ratio.
- Alerts: `ThreatLensAvailabilityBudgetBurnFast` (30-day ratio < 99.5%),
  `ThreatLensAvailabilityBudgetBurnSlow` (1h and 6h multi-window burn),
  `ThreatLensDependencyNotReady`, `ThreatLensHigh5xxRate`,
  `ThreatLensMetricsStale` (availability unobserved).

### 4. How to run the observation window

```powershell
# Start the stack (Compose or Kubernetes) and confirm both surfaces:
curl.exe http://127.0.0.1:8100/health/ready
curl.exe http://127.0.0.1:3000/healthz

# Run the black-box monitor for the full month under a supervisor.
python scripts/availability_monitor.py `
  --api-url http://127.0.0.1:8100 `
  --dashboard-url http://127.0.0.1:3000 `
  --interval 30 `
  --duration-days 30 `
  --state artifacts/verification/availability-monitor.jsonl `
  --report artifacts/verification/availability-monitor-report.json
```

Re-run with `--report-only` to recompute the trailing window at any time. For
production, scrape `/metrics` with Prometheus and retain at least 30 days.

### 5. What has been measured here (honest status)

| Evidence | Result | What it proves |
| --- | --- | --- |
| `nfr_availability_daa3a40f` one-hour sample | 716/716 readiness probes (100%), p95 62.53 ms | No failures in a one-hour isolated sample |
| `nfr_availability_daa3a40f` fault drill | API kill/restart recovery 8,266 ms, no probes dropped after restart | The API restarts and recovers; readiness gates a broken dependency (503) while liveness stays 200 (200) |
| `nfr-availability-drill` enhanced run | See artifact | API + dashboard + PostgreSQL/Redis/search fault isolation + error budget arithmetic |
| `nfr-observability-e6b40b51` | `/metrics` 200 with readiness/dependency/heartbeat/outbox gauges | The measurement surface exists and is scrapeable |

**Status: PARTIAL.** The 99.5% target, the 216-minute budget, the metric, the
rules, the monitor and the fault/recovery behaviour are implemented and
verified. The actual elapsed 30-day production window has not occurred in this
environment, so a monthly availability result is not claimed.

### 6. Runbook

1. **Alert: `ThreatLensDependencyNotReady`.** Call `/health/ready` and
   `/metrics`; check `threatlens_dependency_up{dependency}` to identify
   PostgreSQL, Redis or Elasticsearch. Restore that dependency. `/health/live`
   remaining 200 while `/health/ready` is 503 is the expected isolation
   behaviour; do not restart the API first.
2. **Alert: `ThreatLensAvailabilityBudgetBurnFast`.** Compute the trailing
   window with `python scripts/availability_monitor.py --report-only`. Identify
   the outage interval from the JSONL state file or Prometheus, confirm the
   root cause, and record the incident. Budget is 216 minutes/month.
3. **Alert: `ThreatLensHigh5xxRate`.** Correlate structured API logs by
   correlation ID with `threatlens_requests_total{status=~"5.."}`. Roll back or
   scale per the deployment runbook.
4. **Alert: `ThreatLensMetricsStale`.** Treat availability as unobserved, not
   as healthy. Restore scraping before drawing any SLO conclusion.
5. **Recovery measurement.** After an incident, record time-to-ready from the
   first failed probe to the first successful `/health/ready`, plus the number
   of failed cycles. The drill reports these directly.

### 7. Remaining operator action

Run the monitor or Prometheus scrape continuously for 30 days against the
deployed core API and dashboard, retain the JSONL/Prometheus data, then run
`--report-only`. NFR-04 is MET only if the reported 30-day availability for the
API and dashboard is **≥ 99.5%**.
