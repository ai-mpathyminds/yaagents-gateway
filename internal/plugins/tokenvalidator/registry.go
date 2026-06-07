// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// IssuerRegistry plug-point + ClaimMappings helpers (ADR PI4-yaa-0002).
//
// IssuerRegistry is the plug-point for JWT issuer configuration lookup.
// The default implementation is staticIssuerRegistry (config-driven, loaded
// from the `issuers:` YAML list at Init time). Alternate implementations
// (e.g. a meta-IDP dynamic registry) may replace it without modifying the
// plugin core — the interface is the extension point per ADR PI4-yaa-0002 §6.
package tokenvalidator

import (
	"net/http"
	"strings"
)

// IssuerRegistry resolves per-issuer token-validation configuration from the
// unverified `iss` claim extracted before signature verification.
// Implementations MUST be safe for concurrent use from multiple goroutines.
type IssuerRegistry interface {
	// Lookup returns the IssuerConfig for the given issuer URL.
	// Returns (zero, false) for unknown issuers.
	Lookup(iss string) (IssuerConfig, bool)
}

// IssuerConfig holds per-issuer parameters resolved at token-validation time.
// Currently carries ClaimMappings; Audience and JWKSCacheTTL are future fields
// tracked in ADR PI4-yaa-0002 §Decision for a later PI.
type IssuerConfig struct {
	// ClaimMappings defines optional claim-path → request-header mappings.
	// If all fields are empty, no claim-derived headers are injected
	// (backward-compatible with pre-PI4 configs that omit claim_mappings).
	ClaimMappings ClaimMappings
}

// ClaimMappings defines JSONPath-flavored dotted-path expressions for
// extracting JWT claim values and injecting them as upstream request headers
// before forwarding to the backend.
//
// Path syntax: dot-separated field accessors evaluated top-down over the
// decoded JWT payload JSON object.
//
//	"sub"                  → claims["sub"]
//	"realm_access.roles"   → claims["realm_access"]["roles"]
//
// Empty string means "not configured": that header is not injected.
type ClaimMappings struct {
	Subject string // claim path → X-Actor-Principal  (e.g. "sub", "preferred_username")
	Roles   string // claim path → X-Actor-Roles comma-joined (e.g. "realm_access.roles", "groups")
	Tenant  string // claim path → X-Tenant-ID         (e.g. "tenant_id"; optional)
}

// isConfigured reports whether at least one mapping is non-empty.
// Used to gate header injection — zero ClaimMappings means no injection.
func (cm ClaimMappings) isConfigured() bool {
	return cm.Subject != "" || cm.Roles != "" || cm.Tenant != ""
}

// ── staticIssuerRegistry ──────────────────────────────────────────────────────

// staticIssuerRegistry is the config-driven IssuerRegistry implementation.
// It is built at Init time from the `issuers:` YAML list and is immutable
// thereafter, so concurrent reads require no locks.
type staticIssuerRegistry struct {
	m map[string]IssuerConfig // keyed by issuer URL
}

// Lookup returns the IssuerConfig for iss. Returns (zero, false) for unknown
// issuers (the handler maps this to 401/403 per on_failure config).
func (r *staticIssuerRegistry) Lookup(iss string) (IssuerConfig, bool) {
	if r == nil {
		return IssuerConfig{}, false
	}
	cfg, ok := r.m[iss]
	return cfg, ok
}

// ── claim-resolution helpers ──────────────────────────────────────────────────

// resolveClaim traverses a dot-separated path in claims and returns the leaf
// value, or nil when any segment is absent or a non-map intermediate is
// encountered.
//
// Example: resolveClaim(mc, "realm_access.roles") navigates
// mc["realm_access"]["roles"] and returns whatever lives there ([]any, string, …).
func resolveClaim(claims map[string]any, path string) any {
	if path == "" || len(claims) == 0 {
		return nil
	}
	dot := strings.IndexByte(path, '.')
	if dot < 0 {
		// Leaf: direct key lookup.
		return claims[path]
	}
	head, tail := path[:dot], path[dot+1:]
	nested, ok := claims[head].(map[string]any)
	if !ok {
		return nil
	}
	return resolveClaim(nested, tail)
}

// resolveClaimStr resolves path and coerces the leaf to a non-empty string.
// Returns "" when absent, wrong type, or empty.
func resolveClaimStr(claims map[string]any, path string) string {
	s, _ := resolveClaim(claims, path).(string)
	return s
}

// rolesFromClaim coerces a JWT claim value to a []string of role names.
// Handles string (single role), []any (JSON array), and []string.
// Returns nil for nil, empty, or unsupported types.
func rolesFromClaim(v any) []string {
	switch typed := v.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// ── header injection ──────────────────────────────────────────────────────────

// injectClaimHeaders clones req and injects the claim-mapped upstream request
// headers (X-Actor-Principal, X-Actor-Roles, X-Tenant-ID) according to cm.
// Only headers whose mapped claim resolves to a non-empty value are set;
// empty or missing claims result in the header being absent (not set to "").
// The original request is not mutated.
func injectClaimHeaders(req *http.Request, claims map[string]any, cm ClaimMappings) *http.Request {
	r := req.Clone(req.Context())
	if cm.Subject != "" {
		if sub := resolveClaimStr(claims, cm.Subject); sub != "" {
			r.Header.Set("X-Actor-Principal", sub)
		}
	}
	if cm.Roles != "" {
		if v := resolveClaim(claims, cm.Roles); v != nil {
			if roles := rolesFromClaim(v); len(roles) > 0 {
				r.Header.Set("X-Actor-Roles", strings.Join(roles, ","))
			}
		}
	}
	if cm.Tenant != "" {
		if tid := resolveClaimStr(claims, cm.Tenant); tid != "" {
			r.Header.Set("X-Tenant-ID", tid)
		}
	}
	return r
}
