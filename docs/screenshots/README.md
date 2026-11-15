# Screenshots — captured from the running application

Captured 2026-11-15 from the local production build (`next start` on
`http://localhost:3000`) with the API on `http://127.0.0.1:8100` and the
PostgreSQL, Redis and Elasticsearch services running.

The API for this capture run was pointed at an **isolated demo database**
(`threatlens_demo`), not the read-only production dataset. That database was
filled only through the product's own workflows: indicators via the ingestion
service, and users, alert rules, security events, alerts, an incident, a
timeline, a saved hunt and a report through the HTTP APIs. Indicator values use
the reserved documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`) and
RFC 2606 `.example` domains, so no real host is implicated. No dashboard value
was hardcoded and no image was edited or synthesised.

Why the earlier captures were empty: the production dataset really does contain
0 alerts, 0 incidents and 0 alert rules (the 24k+ indicators were ingested
without correlation rules), so the SOC and incident views correctly rendered
empty queues. The captures below show the same views with genuine records
created by the application.

| File | View | Signed-in role | Notes |
|---|---|---|---|
| `login.png` | Login | — | Real login form |
| `dashboard-executive.png` | Executive overview | `executive` | Risk history, mean active IOC priority, category/source charts from demo data |
| `dashboard-soc.png` | SOC triage | `soc_analyst` | Four correlated alerts, "My queue 4", live channel connected |
| `dashboard-incident-response.png` | Incident response | `incident_responder` | Incident workspace with linked evidence, recorded containment checklist and five-entry append-only timeline |
| `dashboard-threat-hunting.png` | Threat hunting | `threat_hunter` | Saved hunt `Finance C2 pivot` with its search results and ATT&CK techniques |
| `intelligence-library.png` | Intelligence library | `soc_analyst` | Six ingested indicators with scores and provenance |
| `admin-user-management.png` | Identity & access | `administrator` | Seeded accounts covering all six roles |
| `security-engineer-feeds.png` | Feed operations | `security_engineer` | Seven feeds including the disabled `Controlled demo feed`, plus alert rules |
| `reports.png` | Reports & exports | `soc_analyst` | Ready "Incident brief - finance C2" report with PDF download, plus export controls |
| `audit-trail.png` | Audit trail | `administrator` | Immutable action records written by the demo workflow (`auth.login`, `risk_snapshot_captured`, …) |
| `capture-log.json` | — | — | Machine record of the capture run (timestamp, base URL, accounts, files) |

Reproduce: start PostgreSQL, Redis and Elasticsearch, apply migrations to a
separate database, point `DATABASE_URL` at it, create the accounts and data
through the UI/API, start the API on port 8100 and the frontend on port 3000,
then sign in with the matching role for each view. The production dataset was
never modified.
