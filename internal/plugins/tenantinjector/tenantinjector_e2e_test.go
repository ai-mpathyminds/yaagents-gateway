// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// E2E test: tenant-injector webhook resolution end-to-end scenarios (WI-4yaa.PLG-06).
//
// Exercises all 5 PLG-06 acceptance-criteria scenarios through the real
// TenantInjector handler using httptest mock webhook servers (no Docker /
// testcontainers needed — the mock webhook is in-process).
//
// As-shipped contract (ADR PI4-yaa-0003 §Decision, revised B-02):
//   - URL template {principal} substitution (GET by default)
//   - 404 from webhook → on_failure.principal_not_found (default 403)
//   - Network error / connection refused → on_failure.lookup_network_error (default 503)
//   - on_failure: pass-through mode DOES NOT EXIST (rejected per ADR PI4-yaa-0003 §Decision §5)
//
// Reuses helpers from plugin_test.go (same package tenantinjector_test):
//   minimalCfg, initPlugin, requestWithClaims, iamServer, assertVendorError.
//
// Per .claude/rules/integration-test-discipline.md: NO t.Skip / t.Skipf /
// t.SkipNow.  Any infrastructure setup failure is a t.Fatal (fail loud).
//
// Run:  go test ./internal/plugins/tenantinjector/ -run E2E -v
//       Expected runtime: <90s (well within A-4 NFR cap).
package tenantinjector_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestE2E_TenantInjector_WebhookResolution is the main e2e harness.
// Runs all 5 PLG-06 acceptance-criteria scenarios as sub-tests.
// Selected by: go test -run E2E
func TestE2E_TenantInjector_WebhookResolution(t *testing.T) {

	// ── Scenario 1: Webhook success → 200 + X-Tenant-ID + X-Actor-Principal ──
	// Full resolution path: JWT sub claim → {principal} substitution in URL →
	// webhook call → response parse → tenant_id extracted → header injection →
	// upstream forwarded. Asserts both tenant header and principal header.
	t.Run("Scenario1_WebhookSuccess_TenantInjected", func(t *testing.T) {
		srv, count := iamServer(t, map[string]string{"alice": "tenant-acme"})
		p := initPlugin(t, minimalCfg(srv.URL+"/api/v1/principals/{principal}/tenant"))

		var gotTenant, gotPrincipal string
		upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			gotTenant = r.Header.Get("X-Actor-Tenant")
			gotPrincipal = r.Header.Get("X-Actor-Principal")
		})

		req := requestWithClaims(map[string]any{"sub": "alice"})
		rr := httptest.NewRecorder()
		p.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Scenario1: want 200, got %d", rr.Code)
		}
		if gotTenant != "tenant-acme" {
			t.Errorf("Scenario1: X-Actor-Tenant: want %q, got %q", "tenant-acme", gotTenant)
		}
		if gotPrincipal != "alice" {
			t.Errorf("Scenario1: X-Actor-Principal: want %q, got %q", "alice", gotPrincipal)
		}
		if got := count.Load(); got != 1 {
			t.Errorf("Scenario1: webhook call count: want 1, got %d", got)
		}
	})

	// ── Scenario 2: Webhook returns 404 → 403 principal_not_found ─────────────
	// as-shipped: 404 maps to on_failure.principal_not_found (default 403).
	// Note: "on_failure: pass-through" mode does not exist in v2 contract (ADR
	// PI4-yaa-0003 §Decision §5 — REJECTED as tenancy bypass vector).
	// Upstream MUST NOT be called; response is vendor error JSON.
	t.Run("Scenario2_Webhook404_PrincipalNotFound_403", func(t *testing.T) {
		srv, _ := iamServer(t, map[string]string{}) // empty — all lookups 404
		p := initPlugin(t, minimalCfg(srv.URL+"/api/v1/principals/{principal}/tenant"))

		var nextCalled bool
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { nextCalled = true })

		req := requestWithClaims(map[string]any{"sub": "no-such-user"})
		rr := httptest.NewRecorder()
		p.Handler(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Scenario2: 404 from webhook: want 403, got %d", rr.Code)
		}
		if nextCalled {
			t.Error("Scenario2: upstream must NOT be called when principal not found")
		}
		assertVendorError(t, rr, "principal_not_found")
	})

	// ── Scenario 3: Webhook unreachable → 503 lookup_network_error ────────────
	// Connection-refused maps to on_failure.lookup_network_error (default 503).
	// Note: per ADR PI4-yaa-0003, "on_failure: pass-through" is absent; gateway
	// always returns an error status on network failures (no forward-without-tenant).
	// Upstream MUST NOT be called.
	t.Run("Scenario3_WebhookUnreachable_NetworkError_503", func(t *testing.T) {
		// Port 19876 is chosen to be safely unbound on any dev host.
		cfg := minimalCfg("http://127.0.0.1:19876/api/v1/principals/{principal}/tenant")
		cfg["lookup"].(map[string]any)["timeout_ms"] = 150 // short timeout for fast test
		p := initPlugin(t, cfg)

		var nextCalled bool
		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { nextCalled = true })

		req := requestWithClaims(map[string]any{"sub": "any-user"})
		rr := httptest.NewRecorder()
		p.Handler(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("Scenario3: unreachable webhook: want 503, got %d", rr.Code)
		}
		if nextCalled {
			t.Error("Scenario3: upstream must NOT be called when webhook unreachable")
		}
	})

	// ── Scenario 4: Cache hit — second request → webhook NOT called ────────────
	// Two requests for the same principal within cache TTL: webhook must be called
	// exactly once.  The second request is served from the per-principal LRU cache.
	t.Run("Scenario4_CacheHit_WebhookCalledOnce", func(t *testing.T) {
		srv, count := iamServer(t, map[string]string{"bob": "tenant-beta"})
		p := initPlugin(t, minimalCfg(srv.URL+"/api/v1/principals/{principal}/tenant"))

		send := func() int {
			req := requestWithClaims(map[string]any{"sub": "bob"})
			rr := httptest.NewRecorder()
			p.Handler(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rr, req)
			return rr.Code
		}

		if code := send(); code != http.StatusOK {
			t.Fatalf("Scenario4: first request: want 200, got %d", code)
		}
		if code := send(); code != http.StatusOK {
			t.Fatalf("Scenario4: second request (cache hit): want 200, got %d", code)
		}
		if got := count.Load(); got != 1 {
			t.Errorf("Scenario4: cache hit: want 1 webhook call, got %d (cache miss on second request)", got)
		}
	})

	// ── Scenario 5: Cache miss after CacheTTL — webhook called again ───────────
	// After the positive cache TTL expires, the next request triggers a fresh
	// outbound webhook call.  Confirms TTL-based eviction (not LRU-only).
	t.Run("Scenario5_CacheMissAfterTTL_WebhookCalledAgain", func(t *testing.T) {
		srv, count := iamServer(t, map[string]string{"carol": "tenant-gamma"})
		cfg := minimalCfg(srv.URL + "/api/v1/principals/{principal}/tenant")
		cfg["lookup"].(map[string]any)["cache"] = map[string]any{
			"ttl_seconds":          1, // 1 s TTL — expires quickly in test
			"negative_ttl_seconds": 1,
			"max_entries":          1000,
		}
		p := initPlugin(t, cfg)

		send := func() int {
			req := requestWithClaims(map[string]any{"sub": "carol"})
			rr := httptest.NewRecorder()
			p.Handler(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rr, req)
			return rr.Code
		}

		if code := send(); code != http.StatusOK {
			t.Fatalf("Scenario5: first request: want 200, got %d", code)
		}
		if got := count.Load(); got != 1 {
			t.Fatalf("Scenario5: after first request: want 1 webhook call, got %d", got)
		}

		time.Sleep(1100 * time.Millisecond) // wait for TTL to expire

		if code := send(); code != http.StatusOK {
			t.Fatalf("Scenario5: post-TTL request: want 200, got %d", code)
		}
		if got := count.Load(); got != 2 {
			t.Errorf("Scenario5: after TTL expiry: want 2 webhook calls (cache miss), got %d", got)
		}
	})
}
