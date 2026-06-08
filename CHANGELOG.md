# Changelog

All notable changes to `yaagents-gateway` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.4.1] — 2026-06-08 (PATCH — gateway only; SDKs unchanged at v0.4.0)

### Fixed

- **`tenant.ContextMiddleware` not wired** (`cmd/gateway/main.go`): the middleware existed in
  `internal/tenant/tenant.go` since WI-1yaa.GW-2 but was never registered in the mux path,
  causing `X-Tenant-ID` from inbound requests to be silently ignored. The downstream gateway
  received an empty tenant context, triggered `403 TENANT_REQUIRED` on tenant-enforced routes,
  which surfaced as `424 failed_dependency` to the caller. Observed at smoke-tester Check #16
  (`portfolio/REPORTS/smoke/PI4-yaa-launch-764abe4.md §E16`); reproduced in the `agent-graph-ecom`
  multi-service example.

  Fix: `ldr.Chain(tenant.ContextMiddleware(log)(dispatcher))` — ContextMiddleware now runs after
  the plugin chain (tokenvalidator / auth injects `auth.Claims` into context) and before the route
  dispatcher, ensuring tenant ID, actor subject, and actor roles are always available in the
  request context for every proxied request.

  **Upgrade note**: no API or configuration changes; drop-in replacement for v0.4.0.

## [0.4.0] — 2026-06-08

Initial public release.

- Gateway core: reverse proxy with typed-response passthrough, Prometheus metrics, structured JSON
  logging, and graceful shutdown.
- Plugin system: 5 built-in plugins — `token-validator`, `tenant-injector`, `license-check`,
  `prompt-sanitize`, `otel-audit`.
- Agentic REST Profile v0.3 typed-response passthrough (media type preservation, no mangling).
- `/healthz` + `/readyz` + `/metrics` endpoints.
- Correlation-ID and Request-ID propagation.
- GHCR multi-arch image (`linux/amd64`, `linux/arm64`) with Cosign keyless signature + SPDX SBOM.
