// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// E2E test: 2-issuer TokenValidator end-to-end scenarios (WI-4yaa.PLG-03).
//
// Exercises all 6 PLG-03 acceptance-criteria scenarios through the real
// TokenValidator handler using httptest JWKS servers (no Docker / testcontainers
// needed — the mock JWKS servers are in-process).
//
// Per .claude/rules/integration-test-discipline.md: NO t.Skip / t.Skipf /
// t.SkipNow.  Any infrastructure setup failure is a t.Fatal (fail loud).
//
// Run:  go test ./internal/plugins/tokenvalidator/ -run E2E -v
//       Expected runtime: < 30s (well within 120s A-4 NFR cap).
package tokenvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

// ── e2e constants ─────────────────────────────────────────────────────────────

const (
	e2eIssA = "https://idp-a.example.com"
	e2eIssB = "https://idp-b.example.com"
	e2eKidA = "ka"
	e2eKidB = "kb"
	// e2eAud is the single audience token must satisfy (configured globally).
	e2eAud = "expected-app"
)

// ── shared setup ──────────────────────────────────────────────────────────────

// e2eMultiIDPValidator builds a 2-issuer TokenValidator backed by two httptest
// JWKS servers (one per issuer) and returns the validator plus both private keys.
//
// Issuer A carries claim_mappings (subject=preferred_username,
// roles=realm_access.roles, tenant=org_id) to exercise the A-4 NFR:
// "assert per-issuer claim mappers correctly attribute principal."
//
// Issuer B has no claim_mappings (verifies backward-compat: no extra headers).
//
// on_failure overrides: unknown_issuer=403, audience_mismatch=403 (matches
// WI-4yaa.PLG-03 brief scenarios 3 and 4).
func e2eMultiIDPValidator(t *testing.T) (tv *TokenValidator, privA, privB *rsa.PrivateKey) {
	t.Helper()

	privA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("e2e: generate issA RSA key: %v", err)
	}
	privB, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("e2e: generate issB RSA key: %v", err)
	}

	urlA, _ := jwksServer(t, map[string]*rsa.PublicKey{e2eKidA: &privA.PublicKey})
	urlB, _ := jwksServer(t, map[string]*rsa.PublicKey{e2eKidB: &privB.PublicKey})

	tv = &TokenValidator{}
	if err := tv.Init(plugin.NewMapConfig(map[string]any{
		"enabled":    true,
		"algorithms": []string{"RS256"},
		"audiences":  []string{e2eAud},
		"issuers": makeIssuers(
			map[string]any{
				"issuer":   e2eIssA,
				"jwks_url": urlA,
				// claim_mappings — A-4 NFR: principal attribution under test
				"claim_mappings": map[string]any{
					"subject": "preferred_username",
					"roles":   "realm_access.roles",
					"tenant":  "org_id",
				},
			},
			map[string]any{
				"issuer":   e2eIssB,
				"jwks_url": urlB,
				// no claim_mappings — backward-compat path
			},
		),
		"required_claims":  []string{"sub"},
		"propagate_claims": map[string]any{"mode": "all"},
		// Match WI brief: unknown_issuer and audience_mismatch return 403.
		"on_failure": map[string]any{
			"unknown_issuer":    403,
			"audience_mismatch": 403,
		},
	})); err != nil {
		t.Fatalf("e2e: TokenValidator.Init: %v", err)
	}

	return tv, privA, privB
}

// e2eMintToken signs a JWT with the given private key, kid and claims.
func e2eMintToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("e2e: sign token: %v", err)
	}
	return s
}

// e2eResult holds the handler response code and the upstream request (nil when
// the upstream was not called, i.e. the handler rejected the token).
type e2eResult struct {
	code     int
	upstream *http.Request // nil = handler rejected; non-nil = handler passed through
}

// e2eCall invokes tv.Handler with a Bearer tokenStr and returns the result.
// The upstream handler captures the forwarded request for header assertions.
func e2eCall(tv *TokenValidator, tokenStr string) e2eResult {
	var captured *http.Request
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	tv.Handler(next).ServeHTTP(rr, req)
	return e2eResult{code: rr.Code, upstream: captured}
}

// ── TestE2E_TokenValidator_MultiIDP ──────────────────────────────────────────

// TestE2E_TokenValidator_MultiIDP is the main e2e harness.  It runs all 6
// PLG-03 acceptance-criteria scenarios via sub-tests so each reports
// independently.  Selected by: go test -run E2E
func TestE2E_TokenValidator_MultiIDP(t *testing.T) {
	tv, privA, privB := e2eMultiIDPValidator(t)

	// ── Scenario 1: Issuer A — valid token → 200 + claim-mapped headers ──
	// A-4 NFR assertion: "assert per-issuer claim mappers correctly attribute
	// principal" — X-Actor-Principal / X-Actor-Roles / X-Tenant-ID populated
	// from claim_mappings{preferred_username, realm_access.roles, org_id}.
	t.Run("Scenario1_IssuerA_ValidToken_200_ClaimHeaders", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":                "u-alice",
			"preferred_username": "alice",
			"realm_access": map[string]any{
				"roles": []any{"admin", "editor"},
			},
			"org_id": "org-42",
			"aud":    e2eAud,
			"exp":    time.Now().Add(time.Hour).Unix(),
			"iss":    e2eIssA,
		}
		tok := e2eMintToken(t, privA, e2eKidA, claims)
		res := e2eCall(tv, tok)

		if res.code != http.StatusOK {
			t.Fatalf("want 200, got %d", res.code)
		}
		if res.upstream == nil {
			t.Fatal("upstream was not called — handler rejected a valid token")
		}

		// A-4 NFR: per-issuer principal attribution
		if got := res.upstream.Header.Get("X-Actor-Principal"); got != "alice" {
			t.Errorf("X-Actor-Principal: want %q, got %q", "alice", got)
		}
		roles := res.upstream.Header.Get("X-Actor-Roles")
		if !strings.Contains(roles, "admin") || !strings.Contains(roles, "editor") {
			t.Errorf("X-Actor-Roles: want admin and editor, got %q", roles)
		}
		if got := res.upstream.Header.Get("X-Tenant-ID"); got != "org-42" {
			t.Errorf("X-Tenant-ID: want %q, got %q", "org-42", got)
		}
	})

	// ── Scenario 2: Issuer B — valid token → 200; no claim-mapped headers ─
	t.Run("Scenario2_IssuerB_ValidToken_200", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "u-bob",
			"aud": e2eAud,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": e2eIssB,
		}
		tok := e2eMintToken(t, privB, e2eKidB, claims)
		res := e2eCall(tv, tok)

		if res.code != http.StatusOK {
			t.Fatalf("want 200, got %d", res.code)
		}
		if res.upstream == nil {
			t.Fatal("upstream was not called — handler rejected a valid issB token")
		}
		// Issuer B has no claim_mappings — extra headers must be absent.
		if v := res.upstream.Header.Get("X-Actor-Principal"); v != "" {
			t.Errorf("X-Actor-Principal: expected absent for issB, got %q", v)
		}
		if v := res.upstream.Header.Get("X-Tenant-ID"); v != "" {
			t.Errorf("X-Tenant-ID: expected absent for issB, got %q", v)
		}
	})

	// ── Scenario 3: Audience mismatch → 403 ──────────────────────────────
	// Token from issuer A carries an aud value not in the configured list.
	t.Run("Scenario3_AudienceMismatch_403", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "u-charlie",
			"aud": "wrong-app", // not in ["expected-app"]
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": e2eIssA,
		}
		tok := e2eMintToken(t, privA, e2eKidA, claims)
		res := e2eCall(tv, tok)

		if res.code != http.StatusForbidden {
			t.Fatalf("want 403, got %d", res.code)
		}
		if res.upstream != nil {
			t.Error("upstream must NOT be called when audience mismatches")
		}
	})

	// ── Scenario 4: Unknown issuer → 403 ─────────────────────────────────
	// iss claim does not match either configured issuer URL; gateway rejects
	// before attempting JWKS fetch.
	t.Run("Scenario4_UnknownIssuer_403", func(t *testing.T) {
		privUnk, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate unknown-issuer key: %v", err)
		}
		claims := jwt.MapClaims{
			"sub": "u-unknown",
			"aud": e2eAud,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": "https://unknown-idp.example.com",
		}
		tok := e2eMintToken(t, privUnk, "uk", claims)
		res := e2eCall(tv, tok)

		if res.code != http.StatusForbidden {
			t.Fatalf("want 403, got %d", res.code)
		}
		if res.upstream != nil {
			t.Error("upstream must NOT be called for an unknown issuer")
		}
	})

	// ── Scenario 5: JWKS endpoint unreachable (cold-start) → 503 ─────────
	// A separate TokenValidator whose JWKS URL is connection-refused confirms
	// errJWKSUnavailable → 503 path (no cached keys exist on first request).
	t.Run("Scenario5_JWKSUnavailable_503", func(t *testing.T) {
		tvDown := &TokenValidator{}
		if err := tvDown.Init(plugin.NewMapConfig(map[string]any{
			"enabled":    true,
			"algorithms": []string{"RS256"},
			"audiences":  []string{e2eAud},
			"issuers": makeIssuers(map[string]any{
				"issuer":   e2eIssA,
				"jwks_url": "http://127.0.0.1:19998/jwks.json", // never reachable
			}),
			"required_claims":  []string{"sub"},
			"propagate_claims": map[string]any{"mode": "all"},
		})); err != nil {
			t.Fatalf("Init tvDown: %v", err)
		}

		// Token is structurally valid; JWKS cold-start fetch will get
		// connection-refused → errJWKSUnavailable → 503.
		claims := jwt.MapClaims{
			"sub": "u-dave",
			"aud": e2eAud,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iss": e2eIssA,
		}
		tok := e2eMintToken(t, privA, e2eKidA, claims)
		res := e2eCall(tvDown, tok)

		if res.code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", res.code)
		}
		if res.upstream != nil {
			t.Error("upstream must NOT be called when JWKS is unavailable")
		}
	})

	// ── Scenario 6: Expired token → 401 ──────────────────────────────────
	t.Run("Scenario6_ExpiredToken_401", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "u-eve",
			"aud": e2eAud,
			"exp": time.Now().Add(-time.Hour).Unix(), // already expired
			"iss": e2eIssA,
		}
		tok := e2eMintToken(t, privA, e2eKidA, claims)
		res := e2eCall(tv, tok)

		if res.code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", res.code)
		}
		if res.upstream != nil {
			t.Error("upstream must NOT be called for an expired token")
		}
	})
}
