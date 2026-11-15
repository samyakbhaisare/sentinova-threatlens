# Role permission matrix

PRD v1.0 Section 11. Every user has exactly **one** primary role. Permissions are
enforced by the backend on every request (`backend/app/security.py`,
`require(permission)` / `require_stateless(permission)` dependencies); the
frontend only hides controls and is never the access boundary.

Roles: `administrator`, `security_engineer`, `incident_responder`,
`threat_hunter`, `soc_analyst`, `executive`.

## Capability matrix

`Full` = permitted on all records the role can see. `Limited` = permitted only
within the role's context (own assignments, routed alerts, incident-linked
records, own artifacts). `None` = backend returns 403.

| Capability | Admin | Security Engineer | Incident Responder | Threat Hunter | SOC Analyst | Executive |
|---|---|---|---|---|---|---|
| View dashboards | Full | Full | Full | Full | Full | Full |
| Search intelligence | Full | Full | Full | Full | Full | None |
| Enrich / tag indicators | Full | Full | Full | Limited | Full | None |
| Manage alerts | Full | Limited | Full | Limited | Full | None |
| Manage incidents & timeline | Full | None | Full | Limited | Limited | None |
| Saved hunts / export | Full | Full | Full | Full | Limited | None |
| Generate reports | Full | Full | Full | Full | Full | Full |
| Configure feeds & integrations | Full | Full | None | None | None | None |
| Manage users & roles | Full | None | None | None | None | None |
| View audit log | Full | Limited | Limited | None | None | None |

## Backend permission map (source of truth)

| Permission key | Roles granted |
|---|---|
| `dashboard` | all six |
| `report` | all six |
| `search` | all except `executive` |
| `enrich` | administrator, security_engineer, incident_responder, soc_analyst |
| `tag` | all except `executive` |
| `alert` | all except `executive` |
| `hunt` | all except `executive` |
| `export` | all except `executive` |
| `incident` | administrator, incident_responder, soc_analyst, threat_hunter |
| `feed` | administrator, security_engineer |
| `user` | administrator |
| `audit` | administrator, security_engineer, incident_responder |

## Contextual ("limited") rules enforced in addition to the role map

- **Alerts.** `security_engineer` and `threat_hunter` may self-claim an
  unassigned routed alert but cannot reassign, resolve or close it. `soc_analyst`
  sees and acts on alerts routed to them; unrelated analysts receive 403.
- **Incidents.** `soc_analyst` and `threat_hunter` may create incidents and link
  evidence, but only `incident_responder`/`administrator` may change incident
  state or owner. Timeline rows are append-only for every role.
- **Indicators.** `threat_hunter` edits are limited to annotations on records in
  their hunting context; creating feeds/rules/events/indicators is restricted to
  administrator and security_engineer.
- **Artifacts.** Hunts, notifications, widget layouts and reports are owner-scoped.
  Reports additionally enforce the current role and audience; TLP:red-linked
  incident reports are denied for all roles.
- **Audit.** `security_engineer` and `incident_responder` see audit events for
  their operational context, not user/role administration.
- **Executive.** Read-only: dashboards, reports and report downloads only. Raw
  record identifiers are redacted in executive responses.

## Authentication model

| Control | Implementation |
|---|---|
| Password hashing | Argon2id (`argon2-cffi`), per-password salt |
| Access token | HS256 JWT, 10-minute lifetime, `iss`/`aud`/`ver` claims |
| Refresh token | Random 48-byte value, SHA-256 digest at rest, 7-day lifetime, rotation with family reuse revocation |
| Revocation | `users.token_version` increment on role change, disable, password reset |
| Lockout | Failed-attempt counter with back-off after repeated failures |
| MFA | Optional TOTP for privileged roles; secret encrypted AES-256-GCM at rest |
| Audit | Login, logout, failed login, refresh reuse, user/role changes and every state-changing action |

## Verification

- `backend/tests/test_rbac_postgres.py` — 15 real-PostgreSQL tests of the read
  and write matrix, ownership scope, token revocation and admin self-demotion denial.
- `backend/tests/test_security_contracts.py` — hashing, JWT, encryption and
  session contracts.
- `backend/tests/test_workflow_postgres.py` — limited-role self-claim, routed-alert
  denial, incident ownership transfer, append-only timeline.
- Live probes recorded in `docs/VERIFICATION_EVIDENCE.md` (401 unauthenticated,
  403 forbidden, permitted actions succeed).

Demo accounts for all six roles are provisioned by
`scripts/create_demo_accounts.py`; passwords are generated locally and written
only to the git-ignored `demo-credentials.local.txt`.
