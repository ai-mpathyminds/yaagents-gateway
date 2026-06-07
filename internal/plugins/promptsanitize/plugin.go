// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Package promptsanitize implements the prompt-sanitize plugin (PRD §6.2.4).
//
// # Pattern engine
//
// Each entry in the `patterns` list specifies either a `regex` (Go RE2 syntax)
// or a `keywords` list, and an `action` of "reject" or "redact".  Patterns are
// evaluated in declaration order against the raw request body.
//
//   - action: redact — all matches are replaced with "[REDACTED]"; the
//     modified body is forwarded to the next handler.  An INFO log is emitted
//     per pattern hit.
//   - action: reject — the request is rejected immediately with HTTP 412
//     (application/vnd.yaagents.clarification+json).  The first matching
//     reject-action pattern wins; no further patterns are evaluated.
//
// The `strategy` key sets a global default action for patterns that omit
// `action`; it defaults to "reject" (safe default).
//
// LLM-based detection is out of scope for v0.4 Stable; deferred to PI5-yaa.
//
// # Configuration
//
//	prompt-sanitize:
//	  enabled: true
//	  strategy: reject           # global default action
//	  on_match_reject_status: 412   # HTTP status for reject (default 412)
//	  max_body_bytes: 1048576    # body scan cap in bytes (default 1 MB)
//	  patterns:
//	    - name: pii_email
//	      regex: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
//	      action: redact
//	    - name: injection_attempt
//	      keywords: ["ignore previous instructions", "jailbreak"]
//	      action: reject
//
// Registration: init() calls plugin.Register so the gateway wires this plugin
// by import side-effect.
package promptsanitize

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/ai-mpathyminds/yaagents-gateway/internal/reqctx"
	"github.com/ai-mpathyminds/yaagents-gateway/internal/response"
	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

func init() {
	plugin.Register(&PromptSanitize{})
}

const (
	// defaultRejectStatus is HTTP 412 Precondition Failed — architect's B-02
	// direct call; signals the client must correct its payload before retrying.
	defaultRejectStatus = http.StatusPreconditionFailed

	// defaultMaxBodyBytes caps the request body scan to 1 MB.
	defaultMaxBodyBytes = 1 << 20
)

// patternDef is a compiled pattern entry from the config.
type patternDef struct {
	name     string
	re       *regexp.Regexp // non-nil for regex patterns; nil for keyword patterns
	keywords []string       // non-nil for keyword patterns; nil for regex patterns
	action   string         // "reject" or "redact" (empty → resolved from global strategy)
}

// PromptSanitize inspects and optionally modifies the request body before
// forwarding to the upstream handler.  Zero value is valid (enabled=false).
type PromptSanitize struct {
	enabled      bool
	strategy     string       // global default action ("reject" or "redact")
	patterns     []patternDef
	rejectStatus int
	maxBodyBytes int64
}

// Name returns the canonical plugin identifier.
func (p *PromptSanitize) Name() string { return "prompt-sanitize" }

// Init parses and validates the plugin configuration.
//
// Required config keys: none (enabled defaults to false).
// Optional keys: strategy, on_match_reject_status, max_body_bytes, patterns.
// patterns is a list of maps; each map must have at least one of regex/keywords.
// Invalid regex syntax causes Init to return a non-nil error.
func (p *PromptSanitize) Init(cfg plugin.PluginConfig) error {
	p.enabled = cfg.GetBool("enabled")

	p.strategy = cfg.GetString("strategy")
	if p.strategy == "" {
		p.strategy = "reject"
	}

	p.rejectStatus = cfg.GetInt("on_match_reject_status")
	if p.rejectStatus == 0 {
		p.rejectStatus = defaultRejectStatus
	}

	p.maxBodyBytes = int64(cfg.GetInt("max_body_bytes"))
	if p.maxBodyBytes <= 0 {
		p.maxBodyBytes = defaultMaxBodyBytes
	}

	raw := cfg.Raw()
	patternsRaw, _ := raw["patterns"].([]any)
	for i, pr := range patternsRaw {
		pm, ok := pr.(map[string]any)
		if !ok {
			return fmt.Errorf("prompt-sanitize: patterns[%d]: expected map, got %T", i, pr)
		}
		pd, err := compilePattern(pm)
		if err != nil {
			return fmt.Errorf("prompt-sanitize: patterns[%d]: %w", i, err)
		}
		p.patterns = append(p.patterns, pd)
	}
	return nil
}

// compilePattern builds a patternDef from the raw map entry.
func compilePattern(m map[string]any) (patternDef, error) {
	var pd patternDef
	pd.name, _ = m["name"].(string)
	pd.action, _ = m["action"].(string)

	regexStr, hasRegex := m["regex"].(string)
	if hasRegex {
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return pd, fmt.Errorf("invalid regex for pattern %q: %w", pd.name, err)
		}
		pd.re = re
	}

	if kw, ok := m["keywords"]; ok {
		switch typed := kw.(type) {
		case []string:
			pd.keywords = typed
		case []any:
			for j, k := range typed {
				s, ok := k.(string)
				if !ok {
					return pd, fmt.Errorf("pattern %q: keywords[%d] must be string, got %T", pd.name, j, k)
				}
				pd.keywords = append(pd.keywords, s)
			}
		default:
			return pd, fmt.Errorf("pattern %q: keywords must be []string or []any, got %T", pd.name, kw)
		}
	}

	if pd.re == nil && len(pd.keywords) == 0 {
		return pd, fmt.Errorf("pattern %q: must specify at least one of 'regex' or 'keywords'", pd.name)
	}
	return pd, nil
}

// Handler returns middleware that scans the request body against configured
// patterns and either redacts matches or rejects the request.
//
// Processing order:
//  1. If not enabled or no patterns: pass through.
//  2. Read body up to maxBodyBytes.  Oversized bodies bypass scanning.
//  3. Apply patterns in declaration order:
//     - reject-action match → 412 clarification response; processing stops.
//     - redact-action match → all occurrences replaced with "[REDACTED]".
//  4. Forward request with the (possibly modified) body.
func (p *PromptSanitize) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.enabled || len(p.patterns) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Read body, capped at maxBodyBytes + 1 to detect overflow.
		limited := io.LimitReader(r.Body, p.maxBodyBytes+1)
		bodyBytes, err := io.ReadAll(limited)
		_ = r.Body.Close()
		if err != nil {
			slog.Warn("prompt-sanitize: failed to read request body; bypassing scan",
				slog.String("error", err.Error()))
			r.Body = http.NoBody
			next.ServeHTTP(w, r)
			return
		}

		if int64(len(bodyBytes)) > p.maxBodyBytes {
			slog.Warn("prompt-sanitize: request body exceeds max_body_bytes; bypassing scan",
				slog.Int64("max_body_bytes", p.maxBodyBytes),
				slog.Int("body_size", len(bodyBytes)))
			// Restore original body for forwarding.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			next.ServeHTTP(w, r)
			return
		}

		corrID := reqctx.CorrelationID(r.Context())
		reqID := reqctx.RequestID(r.Context())

		body := string(bodyBytes)

		for _, pd := range p.patterns {
			action := pd.action
			if action == "" {
				action = p.strategy
			}

			matched, matchSample := matchPattern(pd, body)
			if !matched {
				continue
			}

			switch action {
			case "reject":
				response.WriteClarification(w, p.rejectStatus, response.ClarificationBody{
					RequiredInputs: []response.RequiredInput{{
						Name: pd.name,
						Description: fmt.Sprintf(
							"Pattern %q matched in request body: %s", pd.name, matchSample),
					}},
					Trace: response.Trace{CorrelationID: corrID, RequestID: reqID},
				})
				return

			case "redact":
				body = redactPattern(pd, body)
				slog.Info("prompt-sanitize: redacted content",
					slog.String("pattern", pd.name),
					slog.String("correlation_id", corrID),
					slog.String("request_id", reqID))
			}
		}

		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

// matchPattern reports whether pd matches body and returns a short sample of
// the first match for use in clarification descriptions.
func matchPattern(pd patternDef, body string) (matched bool, sample string) {
	if pd.re != nil {
		if m := pd.re.FindString(body); m != "" {
			// Truncate very long matches to keep descriptions readable.
			if len(m) > 80 {
				m = m[:80] + "…"
			}
			return true, m
		}
	}
	lower := strings.ToLower(body)
	for _, kw := range pd.keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true, kw
		}
	}
	return false, ""
}

// redactPattern replaces all occurrences of pd's matchers with "[REDACTED]"
// and returns the modified body.
func redactPattern(pd patternDef, body string) string {
	if pd.re != nil {
		return pd.re.ReplaceAllString(body, "[REDACTED]")
	}
	// Keyword redaction: case-insensitive, whole-keyword replacement.
	for _, kw := range pd.keywords {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw))
		body = re.ReplaceAllString(body, "[REDACTED]")
	}
	return body
}

// Shutdown is a no-op; the plugin holds no background resources.
func (p *PromptSanitize) Shutdown(_ context.Context) error { return nil }
