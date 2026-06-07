// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

package response

import (
	"encoding/json"
	"net/http"
)

// ContentTypeClarification is the vendor media type emitted when the
// prompt-sanitize plugin rejects a request that matches a reject-action pattern
// (Agentic REST Profile §clarification handshake, Profile v0.3).
//
// Status code: 412 Precondition Failed (architect's B-02 direct call;
// signals the client must correct its payload before retrying).
const ContentTypeClarification = "application/vnd.yaagents.clarification+json"

// RequiredInput describes one pattern that triggered a rejection.
// The Name is the pattern's configured name; Description is a human-readable
// summary of what matched so clients can build informative error messages.
type RequiredInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ClarificationBody is the canonical shape for
// application/vnd.yaagents.clarification+json.
// Schema: yaagents/schemas/v0.1/agentic-clarification.schema.json (TBD).
type ClarificationBody struct {
	// RequiredInputs lists every pattern that triggered the rejection.
	// At least one entry is always present.
	RequiredInputs []RequiredInput `json:"requiredInputs"`
	// Trace propagates cross-service correlation IDs per Agentic REST Profile §5.
	Trace Trace `json:"trace"`
}

// WriteClarification writes body as application/vnd.yaagents.clarification+json
// with the given HTTP status code (typically 412).
func WriteClarification(w http.ResponseWriter, status int, body ClarificationBody) {
	w.Header().Set("Content-Type", ContentTypeClarification)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
