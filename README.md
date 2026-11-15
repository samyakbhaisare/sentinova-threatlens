# Sentinova ThreatLens

Threat-intelligence and security-operations workspace built from the supplied
Sentinova PRD v1.0. It ingests open-source indicators, scores and correlates
them, routes alerts to the right role, and supports incident response, threat
hunting, reporting, exports and audit.

**Delivery status:** 39 PASS, 2 PARTIAL, 0 FAIL, 0 NOT VERIFIED across the 41
PRD v1.0 requirements. The two PARTIAL rows are environmental limits rather
than missing implementation: NFR-04 needs an elapsed 30-day availability window
and NFR-11 needs a cloud Kubernetes cluster/registry. No cloud deployment or
live vendor subscription is claimed. Full scoreboard:
[docs/FINAL_SUBMISSION_STATUS.md](docs/FINAL_SUBMISSION_STATUS.md).

Screenshots from the running application are in
[docs/screenshots/](docs/screenshots/) with their provenance in
[docs/screenshots/README.md](docs/screenshots/README.md). They were captured
from an isolated demo database filled through the product's own workflows, not
from the read-only production dataset (which contains 0 alerts, 0 incidents and
0 alert rules, so its SOC views correctly render empty queues).

## Implemented functionality

- Ingestion from RSS/JSON/IP-list/STIX/CSV feeds with schedules, retries, TTL
  and per-source accepted/rejected health counters.
- Canonical indicator dedupe, scoring with documented contributions, TLP and
  confidence handling, provenance and enrichment attempts that fail honestly
  when no provider credential exists.
- Correlation rules over indicators and internal security events; alert
  lifecycle (acknowledge, assign, start, resolve, escalate).
- Incidents with linked evidence, append-only classified timeline and a
  containment-review checklist that records decisions but executes no response.
- Full-text and faceted search, saved hunts, ATT&CK technique mapping, risk
  snapshots and per-role dashboards.
- PDF reports (background generation with retry/lease) plus bounded CSV/STIX
  background and downstream exports with TLP filtering.
- Six backend-enforced roles, MFA enrolment, session revocation, password reset
  and a hash-chained audit trail.

## Architecture and stack

- Frontend: Next.js 15, React 19, TypeScript, TanStack Query, Recharts, Leaflet.
- Backend: Python 3.11 container image (3.12 is also supported locally), FastAPI,
  Pydantic, SQLAlchemy, Alembic, Celery.
- Data: PostgreSQL (authoritative records plus transactional outbox), Redis
  (tasks, cache, fan-out), Elasticsearch (search projections).
- Single organization; six roles; no public administrator registration.
- Docker Compose for the full stack plus Kubernetes manifests for deployment.
- See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
  [docs/API.md](docs/API.md).

## Install and run

The supported path is Docker Compose (PostgreSQL, Redis, Elasticsearch, API,
worker, scheduler, frontend):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe scripts/bootstrap.py
docker compose up --build -d
docker compose exec api python -m app.cli create-admin --email your-private-address@example.org
docker compose exec api python -m app.cli configure-feeds
```

`bootstrap.py` refuses to overwrite an existing `.env`; never run it with
example credentials on a public deployment.

Local addresses: UI `http://localhost:3000`, API `http://127.0.0.1:8100`,
OpenAPI UI `http://127.0.0.1:8100/api/docs`. The Compose stack publishes the API
on 8100 rather than 8000; override `API_PORT` if that port is occupied.

### Native development

With PostgreSQL, Redis and Elasticsearch already running and `.env` configured:

```powershell
.\.venv\Scripts\python.exe scripts\manage.py migrate
.\.venv\Scripts\python.exe scripts\manage.py cli create-admin --email your-private-address@example.org
.\.venv\Scripts\python.exe scripts\start_local.py
```

Build the frontend first with `npm.cmd ci` and `npm.cmd run build` in
`frontend/`. Use `npm.cmd` on Windows because PowerShell script execution is
restricted. Existing databases created before the current migration set must
run `migrate` before the Reports view works.

## Demo accounts

```powershell
.\.venv\Scripts\python.exe scripts\create_demo_accounts.py
```

The script creates one account per role if missing and writes unique generated
passwords only to the git-ignored `demo-credentials.local.txt`. It prints no
passwords and never commits them; `--reset-passwords` rotates them.

To demonstrate populated views without touching production data, point
`DATABASE_URL` at a separate database, run `migrate`, create an administrator
and seed records through the UI/API. The screenshots in
[docs/screenshots/](docs/screenshots/) were produced that way using reserved
documentation addresses (`203.0.113.0/24`, `198.51.100.0/24`, `.example`
domains). Walkthrough: [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -m "not integration" -q
.\.venv\Scripts\python.exe scripts\offline_checks.py
cd frontend; npm.cmd run typecheck; npm.cmd run build
```

The service-independent backend suite passes **150 tests with 9 skipped**;
with PostgreSQL, Redis and Elasticsearch running, the full suite (including
integration tests) passes **187 tests**. Type checking, the production
`next build`, and the Playwright suite (13 passed, 1 environment-gated skip)
also pass against the current source. Integration tests use a separate
`threatlens_test` database and controlled fixtures; they never replace live feed
records with fabricated data. Results and evidence:
[docs/VERIFICATION_EVIDENCE.md](docs/VERIFICATION_EVIDENCE.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md), [API](docs/API.md), [deployment](docs/DEPLOYMENT.md), [operations](docs/OPERATIONS.md).
- [Security](docs/SECURITY.md), [role and permission matrix](docs/ROLE_PERMISSION_MATRIX.md).
- [Verification evidence](docs/VERIFICATION_EVIDENCE.md).
- [Demo guide](docs/DEMO_GUIDE.md), [final submission status](docs/FINAL_SUBMISSION_STATUS.md).

## Known limitations

- NFR-04 (monthly availability) and NFR-11 (cloud Kubernetes rollout) are
  PARTIAL for environmental reasons only; no elapsed month or cloud cluster is
  claimed.
- No live commercial threat-intelligence or enrichment credential is present, so
  those calls return recorded failure states instead of data.
- The containment checklist records decisions; it performs no active response.
- The full graphical ATT&CK coverage overlay is a remaining gap; technique IDs
  and coverage counts are shown instead.
- Databases created before migration `0005` must run `scripts/manage.py migrate`
  (or the Compose `migrate` service) before opening Reports.

Provider credentials belong in mounted secret files, never frontend code or
source control. IOC URLs are data, not links for automatic browsing.
