# API usage

## New classified/reference/history/export contracts
- `GET /attack/coverage` returns synchronized reference metadata plus actual active-IOC mapping counts; unknown analyst assertions are explicit. `POST /attack/sync` requires engineering privileges and queues an official MITRE STIX sync.
- `GET /dashboard/risk-history?days=30` returns only stored measurements, with actual capture times and `backfilled=false`. `POST /dashboard/risk-snapshots` queues current capture; the scheduler captures at most one immutable record per UTC hour.
- Background CSV/STIX contracts are documented in the **Background CSV/STIX exports** section below.
- IOC `notes_tlp` and `annotation_tlp`, incident/timeline/report/telemetry `tlp`, and optional `expected_version` on mutable records are documented in the classification and handling policy in [SECURITY.md](SECURITY.md#classification-and-handling-policy). A stale version or forbidden downgrade returns 409.
- Generic PDFs now have included-IOC manifests. A changed source label invalidates an older artifact; unverified legacy PDFs require regeneration. Product reports remain internal amber and never export red narrative.

Base: `/api/v1`. Interactive contract: `/api/docs`; generated schema `/api/openapi.json`. GET health probes and login/refresh/reset are intentionally unauthenticated; business endpoints require a JWT. Metrics should be reachable only on the internal monitoring network.

## Authentication
POST `/auth/login` with `{email,password,totp?}` returns a 10-minute access token and user profile. Refresh credentials are placed in an HttpOnly, SameSite=Strict cookie restricted to `/api/v1/auth`; production sets Secure. Send `Authorization: Bearer <access_token>` on REST requests. POST `/auth/refresh` rotates the cookie; replay revokes its family and invalidates access tokens. POST `/auth/logout` revokes all sessions for the account. GET `/auth/me` returns authoritative permissions.

Administrator-created users default to SOC Analyst. `/users/{id}/reset-token` issues a 15-minute single-use credential for private delivery; `/auth/reset` consumes it. No SMTP delivery is claimed. Privileged users can enroll TOTP via `/auth/mfa/setup` and `/auth/mfa/confirm`.

## Resource domains
Continuation endpoints: PATCH `/alert-rules/{id}` supports explicit null to clear source/category/recipient filters; GET `/assignees` returns minimal enabled operational-user identities; GET `/feeds/{id}/diagnostics`, `/indicators/{id}/history`, and `/alerts/{id}/history` expose authorized evidence. POST `/incidents/{id}/links` appends replay-aware IOC/alert linkage. PATCH `/reports/{id}` supports `{"schedule_hours":null}` to stop a schedule and `{"cancel":true}` to cancel queued work without deleting completed evidence.

| Route | Operations |
|---|---|
| `/users` | Admin list/create; PATCH `/{id}` role/enable |
| `/feeds` | Engineer list/create; PATCH `/{id}`; POST `/{id}/poll` queues work |
| `/indicators` | Search/list; engineer submission; GET/PATCH `/{id}`; POST `/{id}/enrich`, `/{id}/relationships` |
| `/reputation/ip/{value}`, `/domains/{value}/analysis`, `/hash/{value}` | Read persisted analysis, source results and score breakdown |
| `/events` | Authenticated normalized internal event ingestion |
| `/integrations/{siem|edr|ticketing}/events` | Namespaced event ingestion hooks |
| `/alert-rules` | List; engineer create threshold/category/source/recipient rules |
| `/alerts` | Routed queue; PATCH `/{id}` sequential lifecycle/assignee |
| `/incidents` | List/create; PATCH `/{id}`; GET/POST `/{id}/timeline` |
| `/search` | Elasticsearch full-text and type/source/tag/technique/score facets |
| `/hunts`, `/layout`, `/notifications` | Owner-scoped hunts/layout; notifications and read status |
| `/dashboard` | Database-derived aggregates, `days=1..365` |
| `/reports` | Owner-scoped metadata and queued generation; `/{id}/download` |
| `/export/{stix|csv}` | Up to 1000 selected IOC records, TLP-filtered |
| `/audit`, `/system/health` | Contextual audit and engineer health |

List routes are bounded; indicator lists accept `offset`, `limit`, `q`, `type`, `status`, `min_score`. Search bounds pagination to Elasticsearch's default 10,000-result window. Export `ids` is a comma-separated list; omission means all authorized indicators within the limit. Export `audience=public` means TLP:clear; internal exports allow green/amber only for authorized non-analyst roles. Red is always excluded.

## Replay-safe telemetry
Event identity is `(source,external_id)`. Identical replay returns the existing ID; changed payload returns 409. Timestamps require a timezone. Observable types and values use canonical IOC validation. `controlled_test=true` must identify test telemetry. Real integrations should supply stable external event IDs.

Optional `details.target_geo` requires numeric latitude/longitude, two-letter uppercase country, nonempty `source`, and timezone-aware `observed_at`. Target map entries are included only for events with stored IOC sightings. Missing coordinates/provenance produce no map entry; zero coordinates are valid.

Explicit `ids=` on an export means an empty selection; only omission means all permitted records within the bound. Lifecycle reactivation after expiry requires a fresh TTL. Report generation/download rechecks current access; an executive cannot download an earlier technical report from a prior operational role.

Incident PDF generation and download are denied when any currently linked IOC is TLP:red; this also protects incident titles and narrative. Completed files are retained, not deleted. Queued jobs expose the handling-policy failure rather than returning a false completion.

## WebSocket
Connect `/api/v1/ws`, then within five seconds send:
```json
{"access_token":"YOUR_SHORT_LIVED_TOKEN","channels":["alerts.stream","indicators.high_severity"]}
```
Tokens are not placed in URLs. Server validates each subscription, checks account/token validity during the session, and honors alert recipient routing. `incidents.{id}` requires incident access; `system.health` requires engineering privileges. Realtime messages carry IDs; clients refetch authorized current state. This is at-least-once invalidation, not a durable client-delivery guarantee.

The frontend subscribes to the selected incident channel on selection changes. Initial WS authentication JSON is bounded to 16 KiB, access tokens to 4096 characters, and subscriptions to 20 channels. Authentication DB work runs outside the async event loop; connected/rejected/disconnected actions are audited with cancellation-safe cleanup. Actual distributed fanout remains a separate service-backed verification gate.

## Errors
Expected errors use `{error_code,message,correlation_id}`; validation responses additionally name invalid fields without echoing secrets. 401 invalid/expired/revoked credentials; 403 permission/context denial; 409 conflict/invalid transition; 422 schema rejection; 429 request budget; 503 unavailable infrastructure. Outbox requests return 202 queued, never a fabricated completed result.

## Background CSV/STIX exports

These are application intelligence exports, not ZIPs or submission packages. Packaging remains frozen.

### API
- `POST /api/v1/exports` — format (`csv` or `stix`), audience (`public` or `internal`), selection, and `max_records`.
- `GET /api/v1/exports` — current user's latest jobs.
- `GET /api/v1/exports/{id}` — authorized status, initial matching count, written count, cap flag, attempts and integrity digest.
- `POST /api/v1/exports/{id}/cancel` — cancel work or revoke future download; files/history are retained.
- `POST /api/v1/exports/{id}/retry` — retry a failed job within the three-attempt limit.
- `GET /api/v1/exports/{id}/download` — ownership/current-role/source-classification/manifest/integrity validation before streaming.

Example selection (illustrative syntax, not live data):
```json
{"format":"stix","audience":"public","selection":{"q":"example.org","type":"domain","status":"active","min_score":50},"max_records":100000}
```

Supported selection fields: literal value substring, type, status, minimum score, explicit IDs, exact tag, technique ID and source ID. Explicit empty IDs means no selection. Technique filters use normalized mappings. Tag predicates use exact JSON-array membership, with dialect-specific SQL covered at available test boundaries.

### Reliability and limits
- Job and outbox request commit together in PostgreSQL.
- Atomic queued-to-running claims have unique attempt tokens and ten-minute leases; duplicate workers cannot own the same attempt.
- Output uses 500-row keyset pages, up to five million requested rows and a 512 MiB artifact safety bound. At most five queued/running jobs per user.
- The row cap is explicit through `limited`; no hidden legacy 1,000-row cap. `matching_count` is measured at job start; selection is evaluated during streaming and versions/labels are recorded for written rows. This is not a single database-wide point-in-time snapshot.
- Expired worker leases and old queued jobs whose broker messages may have been lost are safely redispatched. Three attempts are allowed. Old per-attempt files/manifests are retained; retries do not overwrite an earlier attempt.
- A file is downloadable only after complete generation and manifest validation. Cancellation, permission changes, classification changes, missing manifests or checksum failure deny access.
- Data files live under `REPORT_DIR/exports`, never the frontend's public directory. No source indicators are fetched as URLs or executed.

### Evidence and remaining gates
Tests generated and read a real **1,205-record CSV**, validated a streamed STIX 2.1 bundle with the STIX library, and exercised duplicate claims, lease/broker recovery, replay, cancellation, failure/retry, exact tag selection, ownership, classification revocation and corruption checks using isolated SQLite storage. This proves the tested contracts, not production PostgreSQL locks, Redis delivery, five-million-row throughput or bounded process RSS under production load.

Download checks are linear in included records and file bytes and hold DB locks through the request transaction. Representative performance/lock-contention tests, artifact retention automation and production encryption remain deployment/verification work.
