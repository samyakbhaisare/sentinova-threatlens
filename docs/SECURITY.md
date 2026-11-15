# Security controls and threat model

## Implemented controls
- Argon2id password hashes; short-lived signed JWT; hashed opaque refresh credentials with rotation/reuse detection, account version revocation and login backoff.
- Backend six-role authorization and contextual checks for incidents, indicator edits, audit, routed alerts, reports, layouts and notifications.
- AES-256-GCM encryption of TOTP secrets with unique nonces and authenticated ciphertext. Feed/provider keys referenced via mounted files; no browser disclosure.
- Parameterized SQLAlchemy queries, strict request schemas, 1 MiB actual-body limit, per-identity Redis request budget and token verification.
- Feed URLs restricted to HTTPS, operator allowlisted hosts, public resolved addresses and no redirects. IOC URLs never fetched.
- CSV formula-prefix neutralization, STIX library serialization, XML escaping in PDF, no remote PDF resource loading, TLP-filtered exports.
- Application database role lacks UPDATE/DELETE/TRUNCATE on evidence tables; triggers reject mutations. Audit entries include actor, correlation ID and content digest.
- Restricted cookies, no localStorage token persistence, same-origin refresh checks; security headers; production gateway TLS/HSTS configuration.

## Threat boundaries and remaining controls
Single-organization deployment is intentional; there is no multi-tenant isolation claim. Refresh session metadata is stored to support revocation (a justified extension to the PRD's stateless suggestion). TLS between all services, encrypted data volumes/backups, cloud secret-manager integration, DNS-rebinding-resistant network egress and least-privilege monitoring exposure require deployment validation. Application hostname validation alone does not prove network-level SSRF protection.

Audit digests detect content changes when compared to trusted checkpoints, but are not an externally anchored hash chain. An owner/superuser could bypass database controls; off-system immutable backups and checkpoint verification are required. One-year retention is an operational policy, not a measured year of history.

Reports exclude TLP:red indicator details; free-text incident notes require an approved organizational classification policy, and the implemented label/inheritance controls are defined in the classification section below. Export audience selection represents organizational policy; this application does not authorize external recipient organizations. Production CSP still allows inline scripts/styles for Next.js and should be migrated to nonce-based enforcement before acceptance.

Optional MFA has setup/confirmation, but recovery codes, administrator-assisted disable and full reenrollment abuse tests remain incomplete. Password reset uses verified administrator delivery, not an implemented email service. No public demo credentials exist.

No active blocking, quarantine, exploitation or malware execution is implemented. The platform records and exports intelligence and containment recommendations only.

## Classification and handling policy

This policy defines the single-organization application's controls. TLP labels govern sharing; internal record access additionally follows the six-role/context matrix. It is not an automatic content classifier or a named-recipient clearance system.

### Stored labels and inheritance
- IOCs retain source-provided TLP in `indicator_sources.tlp`; canonical ingestion keeps the most restrictive label.
- Analyst notes have a stored `notes_tlp`. New notes, tags and technique annotations default to internal amber unless explicitly classified otherwise. An annotation can raise the whole IOC's handling label.
- Incident titles, timeline entries, telemetry and report titles have explicit labels. Incident handling is the maximum of its own label, linked IOCs and timeline labels, computed when read or exported.
- Ordinary edits cannot lower an existing handling label. Legacy unclassified narrative/annotations are conservatively migrated to red; original evidence text is retained. No automated declassification is implemented.
- Aggregate risk summaries contain counts/priority measures and are treated as internal amber reports; they do not expose raw IOC or timeline content to executives.

### Sharing decisions
| Operation | Allowed |
|---|---|
| External reputation/geolocation provider submission | TLP:clear only; current IOC held under a DB row lock during worker submission |
| Public CSV/STIX | Clear only |
| Internal CSV/STIX | Clear/green/amber for eligible roles; SOC Analyst remains clear-only |
| Any red IOC/file export | Denied |
| Incident PDF with red title/narrative/linked evidence | Denied |
| Executive PDF | Current-owner summary only; prior operational artifacts cannot be downloaded as executive summaries |

Classification statements are supplied by trusted sources/authorized analysts. Semantic redaction of wrongly labelled text and named-recipient TLP:red access lists remain outside these implemented controls. Organization policy must establish who is permitted to label/read information.

### Current-state artifact enforcement
Bulk CSV/STIX and PDF source manifests store included IOC IDs, versions and labels. Download checks current role, ownership, completeness and source labels. Even a clear-to-green change invalidates an older clear-marked artifact. Legacy PDFs without a verifiable manifest must be regenerated. Bulk output additionally has a SHA-256 integrity check.

Source share locks and request-scoped transactions are used during download; the isolated PostgreSQL suite verifies the triggers, grants and revision checks, but production lock contention and full streaming transaction lifetime remain deployment gates. Bytes already delivered cannot be revoked. Classified files require encrypted production storage/TLS, which are deployment gates rather than local claims.

### Concurrency
Mutable IOC/alert/rule/incident/report records use ORM optimistic versions. Clients can submit `expected_version`; stale values return 409. Version-aware annotation/lifecycle/rule forms bind displayed data to their version. Legacy callers omitting versions retain sequential last-write behavior, while overlapping stale ORM writes are rejected. The PostgreSQL integration suite covers stale-version and ownership rejection; production lock-contention and streaming-lifetime tests remain a deployment gate.

## Security scan results and unverified gates

### Current classification/export safeguards
Persistent source/narrative labels, conservative legacy backfill, no ordinary downgrade, clear-only provider submission, version-aware writes, PDF/bulk manifests and current-state download checks are implemented. Generic report downloads are revoked after included-source reclassification, including changes within permitted internal classes. CSV formula guards include leading controls/whitespace. Feed transfer now has a total deadline in addition to per-read timeouts.

Local regression includes optimistic stale writes, duplicate export claims, source label changes, owner/role changes, corrupt files and broker/lease recovery. Final Bandit medium/high gate has no findings (one known low false positive); Ruff correctness passes. Dependencies were not changed in this batch; prior dependency scan results remain historical, not a new image/security certification.

Production PostgreSQL lock/stream lifetime, complete authorization abuse coverage, named-recipient TLP:red rules, truthful input classification, encrypted storage/TLS, retention and host-level artifact tampering remain deployment/policy gates. See the classification policy above. No ZIP/package or external deployment action occurred.

### 2026-10-28 continuation
Rechecked the new Python 3.12 verification environment: **pip-audit reports no known vulnerabilities**. Full npm audit (including dev dependencies): **0 vulnerabilities**. Bandit: **0 high, 0 medium, 1 low** documented bearer-label false positive; Ruff correctness gate passes.

Security fixes verified with controlled regressions: IP/query/credential cache isolation; same-origin credentialed pagination; numeric/provider payload validation; default-off geo entitlement gate; empty selected exports; current report-role/audience checks; conservative restricted incident narrative omission; recipient-scoped alert history and WS delivery; cancellation-safe WS auth auditing. API and frontend images build successfully; container image scan results are recorded in the Trivy subsection below. The test evidence does not prove production secret management, network egress, TLS or at-rest encryption.

Final report policy was strengthened further: any incident linked to TLP:red is denied PDF generation and download, including previously generated reports, rather than relying on narrative redaction. This prevents indirect title/note disclosure in that case. Focused report/security tests: 19 passed. Classification of arbitrary analyst free text still requires the documented organizational handling policy.

### Dependency scans
Initial Python audit reported 22 advisory entries across pip 24.0, pytest 8.4.2 and setuptools 65.5.0 (including duplicate advisory listings). Updated local tooling to pip 26.2.1, pytest 9.1.1 and setuptools 84.0.0; requirements now require patched pytest. Subsequent `python -m pip_audit --progress-spinner off` reported **No known vulnerabilities found**.

Initial `npm.cmd audit --omit=dev` reported two vulnerable dependency nodes, including a high-severity PostCSS issue nested under Next.js. Added a compatible PostCSS >=8.5.23 override instead of forcing a major framework rewrite; installation, typecheck, build and repeat production audit passed. Repeat audit: **0 vulnerabilities**.

These are package-advisory results for the installed environment, not container-image or penetration-test acceptance.

### Container image scan (Trivy)

Both images were built locally with `docker compose build` and scanned with Trivy's vulnerability scanner against the current advisory database. `.trivyignore` suppresses only the documented pip-SBOM false positive described underneath the table.

| Image | Base OS | CRITICAL | HIGH | Fixable CRITICAL/HIGH | Residual notes |
| --- | --- | --- | --- | --- | --- |
| `sentinova-threatlens-api:verify` | Debian 13.7 | 0 | 47 | 0 | The 47 HIGH advisories are Debian 13.7 packages with no distro fix published at scan time (`ignore-unfixed` in CI). |
| `sentinova-threatlens-web:verify` | `node:24-alpine` runtime | 0 | 0 | 0 | 1 MEDIUM remains: zlib `CVE-2026-4738`, fixed in `1.4-r0` by a newer Alpine base layer. |

Image hardening applied before the final scan:

- The API Dockerfile now applies distro security updates (`apt-get upgrade`) during the build.
- The frontend runtime stage deletes the build-only `npm`, `npx` and `corepack` trees. Before removal the web image carried 6 fixable HIGH findings from the bundled npm dependency tree (`brace-expansion`, `undici`); the rebuilt image reports none.
- CI fails on fixable CRITICAL/HIGH (`ignore-unfixed: 'true'` plus `.trivyignore`), which both images satisfy.

`.trivyignore` contains `CVE-2025-47273`, `CVE-2026-59890` and `GHSA-xmj3-9gf7-h52w`. All three are setuptools advisories reported from pip's vendored CycloneDX SBOM, which still names setuptools 70.3.0. The runtime package in the built image is setuptools 84.2.1 with pip 26.3, verified by running `python -c "import setuptools, pip; print(setuptools.__version__, pip.__version__)"` inside the image; 84.2.1 is above every listed fix version, and `GHSA-xmj3-9gf7-h52w` is a Windows-only path escape that cannot apply to these Linux images.

### Python static analysis
Initial Bandit scan found a medium-severity shared `/tmp` report-directory concern. Default report storage moved to `/data/reports` (operator-managed mount).

The medium/high gate subsequently passed. Full scan identified two low findings:
- B105 on `token_type: 'bearer'`: a documented false positive. This is the OAuth token-type label, not a password, key or credential.
- B406 on `xml.sax.saxutils.escape`: code used only an escaping helper, not an XML parser. Replaced with `html.escape` to remove the unnecessary XML import. Regression tests/build evidence follow the change.

Final scan after replacement: **0 high, 0 medium, 1 low** (the documented bearer-label false positive). Security-contract regression: 10 passed. Source-handling hardening preserves maximum TLP and rejects unknown/granular STIX markings; its database regression is pending environment recovery.

Docker-free tests cover Argon2 verification, AES-GCM nonce uniqueness/tamper rejection, JWT expiry/audience/issuer/version/disable checks, six-role permissions, strict request schemas, CSV formula safety and STIX parsing. Earlier PostgreSQL tests cover refresh reuse, role denials, TLP restrictions, incident/report context and database privilege checks.

### Unverified gates
- Trivy image scanning: **RUN** for locally built API and web images (see the results table above). Registry-side scanning of published images and continuous re-scan remain **UNVERIFIED**.
- OWASP ZAP, full API abuse suite, complete object-authorization matrix, MFA lifecycle/recovery testing: **UNVERIFIED**.
- Production TLS, storage encryption, network egress and cloud secret-manager integration: **UNVERIFIED**.
- Both images reported zero CRITICAL findings on the scan date, but that is a point-in-time scan of locally built images and is not a production security certification. The 47 Debian HIGH advisories and the single Alpine MEDIUM above are accepted residuals, not fixes.
