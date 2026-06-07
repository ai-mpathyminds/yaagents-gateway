// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Command mockotelcollector is a minimal gRPC OTLP trace collector stub for
// the bench harness.  It accepts every ExportTraceServiceRequest and returns
// an empty OK response, allowing the otelaudit plugin's OTLP exporter path
// to be exercised without a real OpenTelemetry Collector deployment.
//
// Ports (overridable via env):
//
//	GRPC_PORT  (default 4317) — OTLP gRPC trace receiver
//	HTTP_PORT  (default 4318) — /healthz and /metrics endpoints
//
// Used by: WI-4yaa.BENCH-5
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

// mockTraceServer accepts all span exports and returns a success response.
// It is safe for concurrent use — accepted is an atomic counter.
type mockTraceServer struct {
	collectortrace.UnimplementedTraceServiceServer
	accepted atomic.Int64
}

// Export implements TraceServiceServer.  It counts the call and returns OK.
func (s *mockTraceServer) Export(
	_ context.Context,
	_ *collectortrace.ExportTraceServiceRequest,
) (*collectortrace.ExportTraceServiceResponse, error) {
	s.accepted.Add(1)
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

func main() {
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "4317"
	}
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "4318"
	}

	srv := &mockTraceServer{}

	// ── gRPC server ───────────────────────────────────────────────────────────
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("mockotelcollector: listen gRPC :%s: %v", grpcPort, err)
	}
	gs := grpc.NewServer()
	collectortrace.RegisterTraceServiceServer(gs, srv)
	go func() {
		log.Printf("mockotelcollector: gRPC OTLP listening on :%s", grpcPort)
		if err := gs.Serve(lis); err != nil {
			log.Fatalf("mockotelcollector: gRPC serve: %v", err)
		}
	}()

	// ── HTTP server ───────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "mockotelcollector_accepted_total %d\n", srv.accepted.Load())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"accepted":%d}`+"\n", srv.accepted.Load())
	})

	addr := ":" + httpPort
	log.Printf("mockotelcollector: HTTP listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("mockotelcollector: HTTP serve: %v", err)
	}
}
