// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Package otelaudit — e2e harness (WI-4yaa.PLG-15).
//
// Five scenarios exercising the otel-audit plugin end-to-end:
//  1. Stdout exporter: one JSON-log line per request with all AuditEvent fields.
//  2. OTLP exporter: mock gRPC collector receives span; OTLP spec shape verified.
//  3. include_request_body=false (default): body absent from span AND log.
//  4. include_request_body=true: body present in span AND log.
//  5. Correlation-ID propagation: reqctx value → span correlation_id attribute.
//
// Integration-test discipline: NO t.Skip / t.Skipf / t.SkipNow.
// The mock OTLP collector is an in-process gRPC server; no Docker required.
package otelaudit

import (
	"context"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"

	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

// ── mock gRPC OTLP collector ─────────────────────────────────────────────────

// mockOTLPCollector is a minimal TraceService gRPC server that captures every
// ExportTraceServiceRequest for in-process assertion.  It satisfies the OTLP
// spec structural hierarchy:
//
//	ExportTraceServiceRequest → []ResourceSpans → []ScopeSpans → []Span
type mockOTLPCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	mu   sync.Mutex
	reqs []*coltracepb.ExportTraceServiceRequest
}

// Export implements TraceServiceServer.  It appends the incoming request to
// m.reqs and returns a success response to the gRPC client.
func (m *mockOTLPCollector) Export(_ context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	m.mu.Lock()
	m.reqs = append(m.reqs, req)
	m.mu.Unlock()
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

// allSpans flattens all captured ResourceSpans → ScopeSpans → Spans into a
// single slice for convenient per-span assertions.
func (m *mockOTLPCollector) allSpans() []*tracepb.Span {
	m.mu.Lock()
	defer m.mu.Unlock()
	var spans []*tracepb.Span
	for _, req := range m.reqs {
		for _, rs := range req.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
	}
	return spans
}

// spanAttrMap extracts all string-valued attributes from one OTLP span into a
// map[key → stringValue] for easy lookup.
func spanAttrMap(span *tracepb.Span) map[string]string {
	result := make(map[string]string)
	for _, kv := range span.Attributes {
		result[kv.Key] = kv.Value.GetStringValue()
	}
	return result
}

// hasAttrKey returns true if the span carries an attribute with the given key.
func hasAttrKey(span *tracepb.Span, key string) bool {
	for _, kv := range span.Attributes {
		if kv.Key == key {
			return true
		}
	}
	return false
}

// isAllZero returns true when every byte in b is 0x00.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ── harness helpers ───────────────────────────────────────────────────────────

// startMockCollector starts an in-process gRPC OTLP TraceService on a random
// localhost port.  Returns the collector endpoint URL
// ("http://127.0.0.1:<port>") and the collector instance.
// The gRPC server is stopped automatically via t.Cleanup (LIFO, runs before
// the plugin-shutdown cleanup registered by newOTLPPluginE2E).
func startMockCollector(t *testing.T) (string, *mockOTLPCollector) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startMockCollector: net.Listen: %v", err)
	}

	col := &mockOTLPCollector{}
	srv := grpc.NewServer()
	coltracepb.RegisterTraceServiceServer(srv, col)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	return "http://" + lis.Addr().String(), col
}

// newOTLPPluginE2E initialises an OtelAudit plugin through the real Init path
// (BatchSpanProcessor + gRPC OTLP exporter) pointed at the given endpoint.
// A Shutdown cleanup is registered via t.Cleanup; it runs before the mock
// server's GracefulStop (LIFO order) so the final batch is exported before
// the server disappears.
func newOTLPPluginE2E(t *testing.T, endpoint string, includeBody bool) *OtelAudit {
	t.Helper()
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":              true,
		"exporter":             "otlp",
		"otlp_endpoint":        endpoint,
		"include_request_body": includeBody,
	})); err != nil {
		t.Fatalf("newOTLPPluginE2E Init: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	return a
}

// flushOTLP forces the BatchSpanProcessor to export any queued spans to the
// mock collector synchronously.  Must be called after all handler invocations
// and before collector.allSpans() assertions.
func flushOTLP(t *testing.T, a *OtelAudit) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.tp.ForceFlush(ctx); err != nil {
		t.Fatalf("flushOTLP ForceFlush: %v", err)
	}
}

// ── Scenario 1: Stdout exporter — JSON log line with all AuditEvent fields ───

// TestE2E_OtelAudit_Scenario1_StdoutAllFields verifies that the stdout exporter
// emits exactly one slog INFO record per request and that all AuditEvent-aligned
// JSON field names are present with correct values.
func TestE2E_OtelAudit_Scenario1_StdoutAllFields(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, "GET", "/v1/campaigns",
		"", "e2e-corr-1", "e2e-req-1", "tenant-e2e-1", "actor-e2e-1")
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := lc.last()
	if rec == nil {
		t.Fatal("Scenario1: stdout exporter emitted no log record")
	}
	if rec.message != spanName {
		t.Errorf("Scenario1: log message: got %q, want %q", rec.message, spanName)
	}

	// All AuditEvent-aligned camelCase fields (sdk-go JSON schema parity)
	want := map[string]string{
		"eventType":     eventTypeValue,
		"tenantId":      "tenant-e2e-1",
		"actorId":       "actor-e2e-1",
		"operation":     "GET /v1/campaigns",
		"correlationId": "e2e-corr-1",
		"requestId":     "e2e-req-1",
	}
	for k, v := range want {
		if got := rec.attrs[k]; got != v {
			t.Errorf("Scenario1: attr[%q]: got %q, want %q", k, got, v)
		}
	}
	if rec.attrs["timestamp"] == "" {
		t.Error("Scenario1: timestamp field must be present and non-empty")
	}

	// Exactly one log record per request
	if n := lc.count(); n != 1 {
		t.Errorf("Scenario1: log record count: got %d, want 1", n)
	}
}

// ── Scenario 2: OTLP exporter — mock collector receives span (OTLP spec) ─────

// TestE2E_OtelAudit_Scenario2_OTLPCollectorReceivesSpan verifies the full gRPC
// OTLP export path.  The mock collector asserts the OTLP spec structural
// hierarchy (ResourceSpans → ScopeSpans → Span) and validates span identity
// fields (TraceId, SpanId, StartTime, EndTime) and all five standard attributes.
func TestE2E_OtelAudit_Scenario2_OTLPCollectorReceivesSpan(t *testing.T) {
	endpoint, col := startMockCollector(t)
	a := newOTLPPluginE2E(t, endpoint, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, "POST", "/v1/infer",
		"", "e2e-corr-2", "e2e-req-2", "tenant-e2e-2", "actor-e2e-2")
	h.ServeHTTP(httptest.NewRecorder(), req)

	flushOTLP(t, a)

	spans := col.allSpans()
	if len(spans) == 0 {
		t.Fatal("Scenario2: mock OTLP collector received no spans")
	}
	span := spans[0]

	// OTLP spec §3.1: TraceId (16 bytes) and SpanId (8 bytes) must be non-zero.
	if isAllZero(span.TraceId) {
		t.Error("Scenario2: span TraceId must be non-zero (OTLP spec §3.1)")
	}
	if isAllZero(span.SpanId) {
		t.Error("Scenario2: span SpanId must be non-zero (OTLP spec §3.1)")
	}

	// Span name and timing
	if span.Name != spanName {
		t.Errorf("Scenario2: span name: got %q, want %q", span.Name, spanName)
	}
	if span.StartTimeUnixNano == 0 {
		t.Error("Scenario2: StartTimeUnixNano must be > 0")
	}
	if span.EndTimeUnixNano == 0 {
		t.Error("Scenario2: EndTimeUnixNano must be > 0 — span must be ended before export")
	}

	// All five Profile-required span attributes
	attrs := spanAttrMap(span)
	wantAttrs := map[string]string{
		"tenant_id":      "tenant-e2e-2",
		"actor_id":       "actor-e2e-2",
		"operation":      "POST /v1/infer",
		"correlation_id": "e2e-corr-2",
		"request_id":     "e2e-req-2",
	}
	for k, v := range wantAttrs {
		if got := attrs[k]; got != v {
			t.Errorf("Scenario2: span attr[%q]: got %q, want %q", k, got, v)
		}
	}
}

// ── Scenario 3: include_request_body=false — body absent from span AND log ───

// TestE2E_OtelAudit_Scenario3_IncludeBodyFalse_BodyAbsent verifies that the
// default include_request_body=false configuration prevents PII leakage:
// the request body must not appear in the stdout log record or OTLP span.
func TestE2E_OtelAudit_Scenario3_IncludeBodyFalse_BodyAbsent(t *testing.T) {
	const sensitiveBody = "secret-payload-pii-do-not-audit"

	t.Run("stdout", func(t *testing.T) {
		lc := &logCapture{}
		setLogger(t, lc)

		a := newStdoutPlugin(t, false) // include_request_body: false
		req := requestWithCtx(t, "POST", "/v1/chat",
			sensitiveBody, "c3s", "r3s", "t3", "u3")
		a.Handler(passThrough()).ServeHTTP(httptest.NewRecorder(), req)

		rec := lc.last()
		if rec == nil {
			t.Fatal("Scenario3/stdout: no log record emitted")
		}
		if _, ok := rec.attrs["requestBody"]; ok {
			t.Error("Scenario3/stdout: requestBody MUST NOT appear in log when include_request_body=false")
		}
	})

	t.Run("otlp", func(t *testing.T) {
		endpoint, col := startMockCollector(t)
		a := newOTLPPluginE2E(t, endpoint, false) // include_request_body: false
		req := requestWithCtx(t, "POST", "/v1/chat",
			sensitiveBody, "c3o", "r3o", "t3", "u3")
		a.Handler(passThrough()).ServeHTTP(httptest.NewRecorder(), req)
		flushOTLP(t, a)

		spans := col.allSpans()
		if len(spans) == 0 {
			t.Fatal("Scenario3/otlp: no spans received by mock collector")
		}
		if hasAttrKey(spans[0], "request_body") {
			t.Error("Scenario3/otlp: request_body MUST NOT appear in span when include_request_body=false")
		}
	})
}

// ── Scenario 4: include_request_body=true — body present in span AND log ─────

// TestE2E_OtelAudit_Scenario4_IncludeBodyTrue_BodyPresent verifies that the
// opt-in include_request_body=true configuration correctly includes the request
// body in both the stdout log field and the OTLP span attribute.
func TestE2E_OtelAudit_Scenario4_IncludeBodyTrue_BodyPresent(t *testing.T) {
	const auditBody = "audit-me: the full prompt body for compliance recording"

	t.Run("stdout", func(t *testing.T) {
		lc := &logCapture{}
		setLogger(t, lc)

		a := newStdoutPlugin(t, true) // include_request_body: true
		req := requestWithCtx(t, "POST", "/v1/chat",
			auditBody, "c4s", "r4s", "t4", "u4")
		a.Handler(passThrough()).ServeHTTP(httptest.NewRecorder(), req)

		rec := lc.last()
		if rec == nil {
			t.Fatal("Scenario4/stdout: no log record emitted")
		}
		if got := rec.attrs["requestBody"]; got != auditBody {
			t.Errorf("Scenario4/stdout: requestBody: got %q, want %q", got, auditBody)
		}
	})

	t.Run("otlp", func(t *testing.T) {
		endpoint, col := startMockCollector(t)
		a := newOTLPPluginE2E(t, endpoint, true) // include_request_body: true
		req := requestWithCtx(t, "POST", "/v1/chat",
			auditBody, "c4o", "r4o", "t4", "u4")
		a.Handler(passThrough()).ServeHTTP(httptest.NewRecorder(), req)
		flushOTLP(t, a)

		spans := col.allSpans()
		if len(spans) == 0 {
			t.Fatal("Scenario4/otlp: no spans received by mock collector")
		}
		if got := spanAttrMap(spans[0])["request_body"]; got != auditBody {
			t.Errorf("Scenario4/otlp: request_body attr: got %q, want %q", got, auditBody)
		}
	})
}

// ── Scenario 5: Correlation-ID propagation ────────────────────────────────────

// TestE2E_OtelAudit_Scenario5_CorrelationIDPropagation verifies that the
// correlation ID injected into the request context (simulating what the
// upstream X-Correlation-ID middleware does) is faithfully propagated to the
// OTLP span's correlation_id attribute, enabling end-to-end trace linkage.
func TestE2E_OtelAudit_Scenario5_CorrelationIDPropagation(t *testing.T) {
	const (
		wantCorrID = "trace-e2e-propagated-abc123-end-to-end"
		wantReqID  = "req-e2e-propagated-xyz789"
	)

	endpoint, col := startMockCollector(t)
	a := newOTLPPluginE2E(t, endpoint, false)

	// requestWithCtx simulates the upstream correlation-ID middleware that
	// extracts the X-Correlation-ID request header into reqctx.
	req := requestWithCtx(t, "POST", "/v1/run",
		"", wantCorrID, wantReqID, "tenant-e2e-5", "actor-e2e-5")
	a.Handler(passThrough()).ServeHTTP(httptest.NewRecorder(), req)

	flushOTLP(t, a)

	spans := col.allSpans()
	if len(spans) == 0 {
		t.Fatal("Scenario5: mock OTLP collector received no spans")
	}
	attrs := spanAttrMap(spans[0])

	if got := attrs["correlation_id"]; got != wantCorrID {
		t.Errorf("Scenario5: correlation_id propagation: got %q, want %q", got, wantCorrID)
	}
	if got := attrs["request_id"]; got != wantReqID {
		t.Errorf("Scenario5: request_id propagation: got %q, want %q", got, wantReqID)
	}

	// Sanity: span identity fields confirm this is a real sampled span.
	if isAllZero(spans[0].TraceId) {
		t.Error("Scenario5: TraceId must be non-zero — sampled span required for propagation")
	}
}
