// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Command noop is a minimal HTTP server that returns 200 OK for every request.
// Used as the upstream backend in bench/compose.bench.yml so that measured
// latency reflects the gateway plugin chain overhead, not upstream processing.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8121"
	}
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	addr := ":" + port
	log.Printf("noop-upstream listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("noop-upstream: %v", err)
	}
}
