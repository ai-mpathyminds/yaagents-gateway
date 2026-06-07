// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

package tokenvalidator

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── resolveClaim ──────────────────────────────────────────────────────────────

func TestResolveClaim_FlatKey(t *testing.T) {
	claims := map[string]any{"sub": "alice"}
	got := resolveClaim(claims, "sub")
	if got != "alice" {
		t.Fatalf("want %q, got %v", "alice", got)
	}
}

func TestResolveClaim_NestedDotPath(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"admin", "user"},
		},
	}
	got := resolveClaim(claims, "realm_access.roles")
	roles, ok := got.([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("want []any of len 2, got %T %v", got, got)
	}
}

func TestResolveClaim_DeepNested(t *testing.T) {
	claims := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "leaf",
			},
		},
	}
	if got := resolveClaim(claims, "a.b.c"); got != "leaf" {
		t.Fatalf("want %q, got %v", "leaf", got)
	}
}

func TestResolveClaim_MissingSegment(t *testing.T) {
	claims := map[string]any{"sub": "alice"}
	if got := resolveClaim(claims, "missing.path"); got != nil {
		t.Fatalf("want nil for missing segment, got %v", got)
	}
}

func TestResolveClaim_EmptyPath(t *testing.T) {
	claims := map[string]any{"sub": "alice"}
	if got := resolveClaim(claims, ""); got != nil {
		t.Fatalf("want nil for empty path, got %v", got)
	}
}

func TestResolveClaim_EmptyClaims(t *testing.T) {
	if got := resolveClaim(nil, "sub"); got != nil {
		t.Fatalf("want nil for nil claims, got %v", got)
	}
}

func TestResolveClaim_NonMapIntermediate(t *testing.T) {
	// Intermediate is a string, not a map → should return nil.
	claims := map[string]any{"realm_access": "not-a-map"}
	if got := resolveClaim(claims, "realm_access.roles"); got != nil {
		t.Fatalf("want nil when intermediate is non-map, got %v", got)
	}
}

// ── resolveClaimStr ───────────────────────────────────────────────────────────

func TestResolveClaimStr_String(t *testing.T) {
	claims := map[string]any{"preferred_username": "alice@example.com"}
	if got := resolveClaimStr(claims, "preferred_username"); got != "alice@example.com" {
		t.Fatalf("want %q, got %q", "alice@example.com", got)
	}
}

func TestResolveClaimStr_NonString(t *testing.T) {
	claims := map[string]any{"count": 42}
	if got := resolveClaimStr(claims, "count"); got != "" {
		t.Fatalf("want empty string for non-string claim, got %q", got)
	}
}

// ── rolesFromClaim ────────────────────────────────────────────────────────────

func TestRolesFromClaim_StringSingle(t *testing.T) {
	got := rolesFromClaim("admin")
	if len(got) != 1 || got[0] != "admin" {
		t.Fatalf("want [admin], got %v", got)
	}
}

func TestRolesFromClaim_StringEmpty(t *testing.T) {
	if got := rolesFromClaim(""); got != nil {
		t.Fatalf("want nil for empty string, got %v", got)
	}
}

func TestRolesFromClaim_SliceAny(t *testing.T) {
	got := rolesFromClaim([]any{"admin", "user", ""})
	if len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Fatalf("want [admin user], got %v", got)
	}
}

func TestRolesFromClaim_SliceString(t *testing.T) {
	got := rolesFromClaim([]string{"r1", "r2"})
	if len(got) != 2 {
		t.Fatalf("want 2 roles, got %v", got)
	}
}

func TestRolesFromClaim_Nil(t *testing.T) {
	if got := rolesFromClaim(nil); got != nil {
		t.Fatalf("want nil for nil, got %v", got)
	}
}

func TestRolesFromClaim_UnknownType(t *testing.T) {
	if got := rolesFromClaim(42); got != nil {
		t.Fatalf("want nil for unsupported type, got %v", got)
	}
}

func TestRolesFromClaim_EmptySliceAny(t *testing.T) {
	if got := rolesFromClaim([]any{}); got != nil {
		t.Fatalf("want nil for empty []any, got %v", got)
	}
}

// ── staticIssuerRegistry ─────────────────────────────────────────────────────

func TestStaticIssuerRegistry_Found(t *testing.T) {
	reg := &staticIssuerRegistry{
		m: map[string]IssuerConfig{
			"https://idp.example.com": {ClaimMappings: ClaimMappings{Subject: "sub"}},
		},
	}
	cfg, ok := reg.Lookup("https://idp.example.com")
	if !ok {
		t.Fatal("want found, got not-found")
	}
	if cfg.ClaimMappings.Subject != "sub" {
		t.Fatalf("unexpected Subject %q", cfg.ClaimMappings.Subject)
	}
}

func TestStaticIssuerRegistry_NotFound(t *testing.T) {
	reg := &staticIssuerRegistry{m: map[string]IssuerConfig{}}
	_, ok := reg.Lookup("https://unknown.example.com")
	if ok {
		t.Fatal("want not-found for unknown issuer")
	}
}

func TestStaticIssuerRegistry_Nil(t *testing.T) {
	var reg *staticIssuerRegistry
	_, ok := reg.Lookup("any")
	if ok {
		t.Fatal("nil registry must return not-found")
	}
}

// ── injectClaimHeaders ────────────────────────────────────────────────────────

func newDummyRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	return req
}

func TestInjectClaimHeaders_Subject(t *testing.T) {
	cm := ClaimMappings{Subject: "sub"}
	claims := map[string]any{"sub": "alice"}
	req := newDummyRequest(t)
	out := injectClaimHeaders(req, claims, cm)
	if got := out.Header.Get("X-Actor-Principal"); got != "alice" {
		t.Fatalf("X-Actor-Principal: want %q, got %q", "alice", got)
	}
}

func TestInjectClaimHeaders_NestedRoles(t *testing.T) {
	cm := ClaimMappings{Roles: "realm_access.roles"}
	claims := map[string]any{
		"realm_access": map[string]any{
			"roles": []any{"admin", "user"},
		},
	}
	req := newDummyRequest(t)
	out := injectClaimHeaders(req, claims, cm)
	got := out.Header.Get("X-Actor-Roles")
	if got == "" {
		t.Fatal("X-Actor-Roles header not set")
	}
	parts := strings.Split(got, ",")
	if len(parts) != 2 {
		t.Fatalf("want 2 roles, got %v", parts)
	}
}

func TestInjectClaimHeaders_Tenant(t *testing.T) {
	cm := ClaimMappings{Tenant: "tenant_id"}
	claims := map[string]any{"tenant_id": "acme"}
	req := newDummyRequest(t)
	out := injectClaimHeaders(req, claims, cm)
	if got := out.Header.Get("X-Tenant-ID"); got != "acme" {
		t.Fatalf("X-Tenant-ID: want %q, got %q", "acme", got)
	}
}

func TestInjectClaimHeaders_MissingClaim_NoHeader(t *testing.T) {
	cm := ClaimMappings{Subject: "preferred_username", Tenant: "tid"}
	claims := map[string]any{} // neither claim present
	req := newDummyRequest(t)
	out := injectClaimHeaders(req, claims, cm)
	if v := out.Header.Get("X-Actor-Principal"); v != "" {
		t.Fatalf("expected absent header, got %q", v)
	}
	if v := out.Header.Get("X-Tenant-ID"); v != "" {
		t.Fatalf("expected absent header, got %q", v)
	}
}

func TestInjectClaimHeaders_DoesNotMutateOriginal(t *testing.T) {
	cm := ClaimMappings{Subject: "sub"}
	claims := map[string]any{"sub": "alice"}
	req := newDummyRequest(t)
	_ = injectClaimHeaders(req, claims, cm)
	// original must not carry the header
	if v := req.Header.Get("X-Actor-Principal"); v != "" {
		t.Fatalf("original request was mutated: got %q", v)
	}
}

func TestInjectClaimHeaders_AllThree(t *testing.T) {
	cm := ClaimMappings{
		Subject: "preferred_username",
		Roles:   "realm_access.roles",
		Tenant:  "org_id",
	}
	claims := map[string]any{
		"preferred_username": "bob",
		"realm_access": map[string]any{
			"roles": []any{"editor"},
		},
		"org_id": "org-42",
	}
	req := newDummyRequest(t)
	out := injectClaimHeaders(req, claims, cm)
	if got := out.Header.Get("X-Actor-Principal"); got != "bob" {
		t.Fatalf("X-Actor-Principal want %q got %q", "bob", got)
	}
	if got := out.Header.Get("X-Actor-Roles"); got != "editor" {
		t.Fatalf("X-Actor-Roles want %q got %q", "editor", got)
	}
	if got := out.Header.Get("X-Tenant-ID"); got != "org-42" {
		t.Fatalf("X-Tenant-ID want %q got %q", "org-42", got)
	}
}

// ── isConfigured ─────────────────────────────────────────────────────────────

func TestClaimMappings_IsConfigured(t *testing.T) {
	if (ClaimMappings{}).isConfigured() {
		t.Fatal("zero ClaimMappings must not be configured")
	}
	if !(ClaimMappings{Subject: "sub"}).isConfigured() {
		t.Fatal("ClaimMappings with Subject must be configured")
	}
	if !(ClaimMappings{Roles: "roles"}).isConfigured() {
		t.Fatal("ClaimMappings with Roles must be configured")
	}
	if !(ClaimMappings{Tenant: "tid"}).isConfigured() {
		t.Fatal("ClaimMappings with Tenant must be configured")
	}
}
