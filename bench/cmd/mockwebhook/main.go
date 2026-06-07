// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Command mockwebhook is a minimal tenant-directory stub for the bench harness.
//
// Behaviour:
//   - Any GET request returns {"tenant_id":"bench-tenant","principal":<last-path-segment>}.
//   - /healthz returns 200 "ok".
//   - /metrics returns a plain-text request count for cache-hit-rate measurement.
//
// Every request is logged to stderr with a running counter so docker-logs
// inspection reveals how many real lookups the tenant-injector plugin made
// (= cache miss count) during a bench run.
//
// Reference: WI-4yaa.BENCH-2
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

var requestCount atomic.Int64

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8122"
	}

	mux := http.NewServeMux()

	// /healthz — liveness probe for compose healthcheck.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// /metrics — request count for cache-hit-rate measurement.
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "mockwebhook_requests_total %d\n", requestCount.Load())
	})

	// Catch-all: return tenant JSON for any path (simulates tenant-directory lookup).
	// The last path segment is treated as the principal identifier.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)

		// Extract principal from last path segment (URL may be /tenants/<principal>).
		path := strings.TrimRight(r.URL.Path, "/")
		parts := strings.Split(path, "/")
		principal := parts[len(parts)-1]
		if principal == "" {
			principal = "unknown"
		}

		log.Printf("[%d] lookup principal=%q", n, principal)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]string{
			"tenant_id": "bench-tenant",
			"principal": principal,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("mockwebhook: encode error: %v", err)
		}
	})

	addr := ":" + port
	log.Printf("mockwebhook listening on %s (tenant-directory stub)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("mockwebhook: %v", err)
	}
}
