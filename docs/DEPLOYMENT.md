# Deployment guide and current status

## Current status
The local stack is operational. PostgreSQL 17, Redis 7 and Elasticsearch 8 run
as Compose data services, and the complete backend suite passes against them
(**187 passed**, 2026-11-15). The API and frontend images build from the current
source, `docker compose config` validates, and both Dockerfiles pass
`docker build --check`. The isolated `sentinova-verify` overlay and
`deploy/local-kind` manifests are verification aids, not a production
deployment. No cloud Kubernetes cluster, public URL or trusted-CA TLS is
claimed.

## Local Compose
Preserve `.env`, `secrets/` and existing volumes. Start the stack with `docker compose up --build -d` after the Docker daemon is available. PostgreSQL initialization creates a separate application login; the migration service uses the owner credential and then revokes evidence mutation grants. All host-published ports bind to loopback. Redis/Elasticsearch security is disabled only in this development network; do not publish this configuration to the internet. Constrained hosts should build images only when needed and keep Docker's data disk separate from the system drive where possible.

Services: postgres, redis, elasticsearch, migrate, api, worker (ingestion/operations queues), dispatcher (maintenance queue), scheduler, frontend. Independent dispatcher capacity prevents a large poll from blocking outbox delivery. Search bulk writes retain undelivered records on failure. PostgreSQL/Redis/search/report data use named volumes.

Production frontend Dockerfile sets the internal API origin at build time. The native build uses `127.0.0.1:8100`. Public WebSockets use the same ingress in production and port 8100 for local UI on port 3000.

Validation: `python scripts/verify_deployment.py` (Compose/Kubernetes) and `curl.exe http://127.0.0.1:8100/health/ready`; authenticated checks and required workers must also pass. A 200 login page is not full-stack validation.

## Kubernetes
1. Provision managed PostgreSQL, Redis and Elasticsearch/OpenSearch-compatible infrastructure, TLS identities and encrypted storage. Elasticsearch DSL compatibility must be tested if substituting OpenSearch.
2. Build/scan/tag API and frontend images. Replace `threatlens-api:release` and `threatlens-frontend:release` via Kustomize image overrides with actual registry references/digests.
3. Supply `threatlens-runtime` from the cloud secret manager: DATABASE_URL (TLS required), REDIS_URL (`rediss://`), SEARCH_URL (HTTPS/auth), JWT_SECRET or file reference, ENCRYPTION_KEY or file reference, ORIGIN, PRODUCTION=true. Supply provider secret files through `threatlens-providers` and an actual certificate in `threatlens-tls`.
4. Apply reviewed database migrations using a separate owner credential and `deploy/grants.sql`; runtime processes must never use the owner login.
5. Supply an RWX storage class for reports. Configure ingress host/DNS and TLS1.2+ controller policy; restrict egress to managed backing services and approved provider endpoints.
6. Render `kubectl kustomize deploy/kubernetes`, review, then apply with authorized cluster credentials and verify rollouts/readiness, WebSocket upgrade, backup/restore and access policies.

Local verification: `deploy/local-kind` runs the same base manifests on a
single-node kind v1.37.0 cluster with the current-source images, isolated
PostgreSQL/Redis/Elasticsearch from `sentinova-verify`, a ReadWriteOnce reports
PVC and one replica per Deployment. It proved 6/6 pods Ready, bound storage,
API/dashboard probes, dependency gauges and 12.78 s pod self-healing. This is a
real Kubernetes control plane but **not** a cloud deployment.

Only local manifest rendering and the local kind rollout have passed. No cloud
Kubernetes cluster, staging/production domain, cloud registry push, image scan or
live URL is claimed. CI provides build/test/scan gates; registry promotion and
cloud rollout are not configured without credentials.
