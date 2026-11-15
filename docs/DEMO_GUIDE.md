# Role-based demonstration guide

## Prerequisites
Repair the environment externally, start backing services, apply migrations, create private role accounts and verify readiness. Configure actual feeds and show successful timestamps. Do not claim currently broken Docker services work. For a frontend-only walkthrough, the login page can be inspected without backing services.

## Real-intelligence walkthrough
1. Security Engineer opens Feed operations, inspects independent schedules/health and re-polls an enabled source. Confirm database-backed accepted/rejected counts.
2. Open Intelligence library; filter canonical IOCs, inspect provenance and score contributions. Explain source-policy reliability versus reported confidence.
3. Request enrichment only when provider credentials/usage rights exist. Show blocked/error outcomes honestly when absent.
4. Use a dedicated test installation for controlled telemetry and an alert rule. Label every fixture. The production application must not present synthetic events as live incidents.

## Role workflows
- **SOC Analyst:** open routed alert → acknowledge → inspect indicator → enrich → escalate. Browser E2E harness must verify click count; no measured <=4-click claim yet.
- **Incident Responder:** inspect linked evidence and chronological timeline, append an action, document containment review (no active enforcement), request an incident PDF.
- **Threat Hunter:** full-text query plus facets, save/reload hunt, inspect relationship edges/ATT&CK IDs, export permitted findings. Full graphical ATT&CK coverage overlay is a remaining gap.
- **Executive:** aggregate risk/volume/category/activity summary, save widget selection and request an executive PDF. No IOC search or operational mutation privilege.
- **Security Engineer:** source configuration/health, alert-rule setup and integration event contract; no user administration.
- **Administrator:** create/disable users, assign role and inspect audit. Demonstrate session revocation using an isolated test user.

## Handling evidence
Use backend-generated PDFs and valid STIX/CSV downloads. Public exports exclude restricted TLP classes. Show empty states rather than seeded fake metrics. Screenshots are valid only if captured from the running application; login-only screenshots do not prove dashboards or integration acceptance.
