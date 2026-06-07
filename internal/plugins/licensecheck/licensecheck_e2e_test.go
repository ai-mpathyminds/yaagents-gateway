// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// E2E harness for the licensecheck plugin (WI-4yaa.PLG-09).
//
// Exercises the full allow/deny matrix against an httptest stub license-server —
// no Docker or external infra required.  All helpers (newPlugin, hitCounter,
// hangServer, decodeError) are defined in plugin_test.go (same package).
//
// Integration-test-discipline: no t.Skip / t.Skipf / t.SkipNow calls permitted.
// CI assert-step greps this file before running; comment-only lines are excluded.
//
// Run: go test -count=1 -timeout 90s -run E2E -v ./internal/plugins/licensecheck/...
package licensecheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ai-mpathyminds/yaagents-gateway/internal/response"
	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

// TestE2E_LicenseCheck_AllowDenyMatrix exercises the six canonical scenarios
// against the as-shipped single-backend contract (PLG-09 acceptance criteria).
func TestE2E_LicenseCheck_AllowDenyMatrix(t *testing.T) {

	// Scenario 1 — token present, license-server validates → 200 pass-through.
	t.Run("Scenario1_ValidToken_200PassThrough", func(t *testing.T) {
		srvURL, _, _ := hitCounter(t, http.StatusOK)
		lc := newPlugin(t, srvURL, nil)

		var upstreamCalled bool
		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			upstreamCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set("X-License-Token", "valid-license-tok")
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want 200", rr.Code)
		}
		if !upstreamCalled {
			t.Error("upstream must be called on valid token")
		}
	})

	// Scenario 2 — token present, license-server returns non-2xx → 403 with
	// vendor error Content-Type.
	t.Run("Scenario2_InvalidToken_403VendorError", func(t *testing.T) {
		srvURL, _, _ := hitCounter(t, http.StatusUnauthorized)
		lc := newPlugin(t, srvURL, nil)

		var upstreamCalled bool
		upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			upstreamCalled = true
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set("X-License-Token", "expired-tok")
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status: got %d, want 403", rr.Code)
		}
		if upstreamCalled {
			t.Error("upstream must NOT be called on invalid token")
		}
		ct := rr.Header().Get("Content-Type")
		if ct != response.ContentTypeError {
			t.Errorf("Content-Type: got %q, want %q", ct, response.ContentTypeError)
		}
		body := decodeError(t, rr)
		if body.Code != "license_invalid" {
			t.Errorf("body.Code: got %q, want license_invalid", body.Code)
		}
		// No dependency trace — server answered (no network failure).
		if body.Trace.Dependency != "" {
			t.Errorf("Trace.Dependency: got %q, want empty for HTTP policy rejection", body.Trace.Dependency)
		}
	})

	// Scenario 3 — token header absent → 403.
	// When no X-License-Token header is present, the plugin calls verify() with
	// an empty token (no Authorization header set).  A compliant license-server
	// rejects the unauthenticated call with 401, mapping to 403 at the plugin.
	t.Run("Scenario3_TokenAbsent_403", func(t *testing.T) {
		srvURL, calls, _ := hitCounter(t, http.StatusUnauthorized)
		lc := newPlugin(t, srvURL, nil)

		var upstreamCalled bool
		upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			upstreamCalled = true
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		// Deliberately omit X-License-Token header.
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status: got %d, want 403", rr.Code)
		}
		if upstreamCalled {
			t.Error("upstream must NOT be called when token is absent")
		}
		// The plugin still consults the license server (empty token → no auth header
		// → server rejects); verify that the outbound call occurred.
		if n := calls.Load(); n == 0 {
			t.Error("license-server should have been consulted even for absent token")
		}
	})

	// Scenario 4 — license-server unreachable (connection refused) → 503 with
	// dependency: "license-server" in trace.
	t.Run("Scenario4_Unreachable_503WithDependency", func(t *testing.T) {
		// Port 19878 — nothing listening; connection will be refused immediately.
		lc := newPlugin(t, "http://127.0.0.1:19878", nil)

		var upstreamCalled bool
		upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			upstreamCalled = true
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set("X-License-Token", "tok-unreachable")
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("status: got %d, want 503 (connection refused is a transient backend failure)", rr.Code)
		}
		if upstreamCalled {
			t.Error("upstream must NOT be called when license-server is unreachable")
		}
		body := decodeError(t, rr)
		if body.Trace.Dependency != "license-server" {
			t.Errorf("Trace.Dependency: got %q, want %q", body.Trace.Dependency, "license-server")
		}
	})

	// Scenario 5 — license-server timeout (timeout_seconds exceeded) → 503 with
	// dependency: "license-server" in trace.
	t.Run("Scenario5_Timeout_503WithDependency", func(t *testing.T) {
		srvURL := hangServer(t)
		// 1 ms timeout ensures the test completes quickly.
		shortClient := &http.Client{Timeout: 1 * time.Millisecond}
		lc := newPlugin(t, srvURL, shortClient)

		var upstreamCalled bool
		upstream := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			upstreamCalled = true
		})

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set("X-License-Token", "tok-timeout")
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("status: got %d, want 503 (timeout is a transient backend failure)", rr.Code)
		}
		if upstreamCalled {
			t.Error("upstream must NOT be called on timeout")
		}
		body := decodeError(t, rr)
		if body.Trace.Dependency != "license-server" {
			t.Errorf("Trace.Dependency: got %q, want %q", body.Trace.Dependency, "license-server")
		}
	})

	// Scenario 6 — cache hit within TTL + LRU eviction at max_cache_size boundary.
	//
	// Part A: same token within TTL → license-server NOT called on 2nd request.
	// Part B: fill cache to max_cache_size (4), add 5th token → LRU entry evicted;
	//         re-requesting evicted token causes a new outbound call.
	t.Run("Scenario6_CacheHitAndLRUEviction", func(t *testing.T) {
		srvURL, calls, _ := hitCounter(t, http.StatusOK)
		// max_cache_size: 4 is baked into newPlugin (matching unit tests).
		lc := newPlugin(t, srvURL, nil)

		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		doReq := func(tok string) int {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			req.Header.Set("X-License-Token", tok)
			rr := httptest.NewRecorder()
			lc.Handler(upstream).ServeHTTP(rr, req)
			return rr.Code
		}

		// Part A — cache hit: two requests with identical token → 1 outbound call.
		doReq("cache-tok") // cache miss → 1 outbound call
		if n := calls.Load(); n != 1 {
			t.Fatalf("after first request: calls=%d, want 1", n)
		}
		doReq("cache-tok") // cache hit → no extra outbound call
		if n := calls.Load(); n != 1 {
			t.Errorf("cache hit: calls=%d, want 1 (second request must be served from cache)", n)
		}

		// Part B — LRU eviction: fill cache then add a 5th token.
		// After Part A, "cache-tok" is in the cache (1 of 4 slots).
		// Add 3 more distinct tokens to fill the remaining 3 slots.
		doReq("t1") // calls=2; "cache-tok" → MRU, "t1" → 2nd
		doReq("t2") // calls=3
		doReq("t3") // calls=4; cache now full: {t3,t2,t1,cache-tok} (front=MRU)
		if n := calls.Load(); n != 4 {
			t.Fatalf("after filling cache: calls=%d, want 4", n)
		}

		// 5th distinct token evicts the LRU entry ("cache-tok" — it was pushed to
		// the back by 3 subsequent inserts and has not been accessed since Part A).
		doReq("t4") // calls=5; "cache-tok" is evicted; cache: {t4,t3,t2,t1}
		if n := calls.Load(); n != 5 {
			t.Fatalf("after 5th token: calls=%d, want 5", n)
		}

		// t1..t4 must still be cached (no new outbound calls).
		before := calls.Load()
		for _, tok := range []string{"t1", "t2", "t3", "t4"} {
			doReq(tok)
		}
		if n := calls.Load(); n != before {
			t.Errorf("t1..t4 should be cached: %d extra calls, want 0", calls.Load()-before)
		}

		// Re-requesting evicted "cache-tok" → cache miss → new outbound call.
		doReq("cache-tok")
		if n := calls.Load(); n != before+1 {
			t.Errorf("evicted cache-tok re-request: calls=%d, want %d (should be a cache miss)", calls.Load(), before+1)
		}
	})
}

// TestE2E_LicenseCheck_CachePlugin builds a plugin with a tiny TTL to verify
// that the custom-TTL construction path used by licensecheck also works in e2e
// context (exercises the Init → cache → expire → re-fetch chain end-to-end).
func TestE2E_LicenseCheck_CacheTTL(t *testing.T) {
	srvURL, calls, _ := hitCounter(t, http.StatusOK)

	lc := &LicenseCheck{}
	cfg := plugin.NewMapConfig(map[string]any{
		"license_url":       srvURL,
		"cache_ttl_seconds": 1,
		"max_cache_size":    4,
	})
	if err := lc.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	doReq := func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
		req.Header.Set("X-License-Token", "ttl-e2e-tok")
		rr := httptest.NewRecorder()
		lc.Handler(upstream).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("status: got %d, want 200", rr.Code)
		}
	}

	doReq() // cache miss → 1 outbound call
	if n := calls.Load(); n != 1 {
		t.Fatalf("after first request: calls=%d, want 1", n)
	}
	doReq() // cache hit within 1-second TTL
	if n := calls.Load(); n != 1 {
		t.Errorf("within TTL: calls=%d, want 1 (cache hit)", n)
	}

	// Sleep past the 1-second TTL so the entry expires.
	time.Sleep(1100 * time.Millisecond)

	doReq() // expired → cache miss → 2nd outbound call
	if n := calls.Load(); n != 2 {
		t.Errorf("after TTL expiry: calls=%d, want 2 (expired entry must trigger re-fetch)", n)
	}
}
