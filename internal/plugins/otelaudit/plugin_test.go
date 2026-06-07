// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

package otelaudit

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ai-mpathyminds/yaagents-gateway/internal/reqctx"
	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

// ── slog capture ─────────────────────────────────────────────────────────────

// logRecord holds one captured slog INFO record.
type logRecord struct {
	message string
	attrs   map[string]string
}

// logCapture is a slog.Handler that captures every record emitted during a test.
type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

func (lc *logCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (lc *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := logRecord{
		message: r.Message,
		attrs:   make(map[string]string),
	}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	lc.mu.Lock()
	lc.records = append(lc.records, rec)
	lc.mu.Unlock()
	return nil
}

func (lc *logCapture) WithAttrs(_ []slog.Attr) slog.Handler { return lc }
func (lc *logCapture) WithGroup(_ string) slog.Handler      { return lc }

// last returns a copy of the most-recently captured record, or nil.
func (lc *logCapture) last() *logRecord {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if len(lc.records) == 0 {
		return nil
	}
	cp := lc.records[len(lc.records)-1]
	return &cp
}

// count returns the number of captured records.
func (lc *logCapture) count() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return len(lc.records)
}

// setLogger replaces the default slog logger for the duration of the test.
func setLogger(t *testing.T, h slog.Handler) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// ── plugin helpers ────────────────────────────────────────────────────────────

// newStdoutPlugin creates an enabled stdout-exporter plugin via Init.
func newStdoutPlugin(t *testing.T, includeBody bool) *OtelAudit {
	t.Helper()
	a := &OtelAudit{}
	cfg := plugin.NewMapConfig(map[string]any{
		"enabled":              true,
		"exporter":             "stdout",
		"include_request_body": includeBody,
	})
	if err := a.Init(cfg); err != nil {
		t.Fatalf("Init(stdout): %v", err)
	}
	return a
}

// newOTLPPlugin creates an enabled OTLP-exporter plugin using initWithExporter
// and a tracetest.InMemoryExporter for in-process span capture.
func newOTLPPlugin(t *testing.T, includeBody bool) (*OtelAudit, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	a := &OtelAudit{
		enabled:        true,
		exporterType:   "otlp",
		includeReqBody: includeBody,
	}
	if err := a.initWithExporter(exp); err != nil {
		t.Fatalf("initWithExporter: %v", err)
	}
	return a, exp
}

// passThrough is a no-op upstream handler that responds 200 OK.
func passThrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// requestWithCtx builds an httptest.Request pre-loaded with reqctx values.
func requestWithCtx(t *testing.T, method, path, body,
	corrID, reqID, tenantID, actor string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := req.Context()
	ctx = reqctx.WithCorrelationID(ctx, corrID)
	ctx = reqctx.WithRequestID(ctx, reqID)
	ctx = reqctx.WithTenantID(ctx, tenantID)
	ctx = reqctx.WithActorSubject(ctx, actor)
	return req.WithContext(ctx)
}

// ── Name ─────────────────────────────────────────────────────────────────────

func TestName(t *testing.T) {
	a := &OtelAudit{}
	if got := a.Name(); got != pluginName {
		t.Errorf("Name(): got %q, want %q", got, pluginName)
	}
}

// ── Init — exporter defaults ──────────────────────────────────────────────────

func TestInit_NoExporter_DefaultsToStdout(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{"enabled": true})); err != nil {
		t.Fatalf("Init with no exporter: unexpected error: %v", err)
	}
	if a.exporterType != "stdout" {
		t.Errorf("exporterType: got %q, want %q", a.exporterType, "stdout")
	}
}

func TestInit_ExplicitStdout_OK(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":  true,
		"exporter": "stdout",
	})); err != nil {
		t.Fatalf("Init(stdout): unexpected error: %v", err)
	}
}

func TestInit_UnknownExporter_Error(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":  true,
		"exporter": "kafka",
	})); err == nil {
		t.Fatal("Init with unknown exporter: expected error, got nil")
	}
}

// ── Init — disabled ───────────────────────────────────────────────────────────

func TestInit_Disabled_OK(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{"enabled": false})); err != nil {
		t.Fatalf("Init(disabled): unexpected error: %v", err)
	}
	if a.enabled {
		t.Error("plugin should be disabled")
	}
}

func TestInit_Disabled_BadExporter_OK(t *testing.T) {
	// Disabled plugin must not reject even a bogus exporter value —
	// it returns before reaching the exporter switch.
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":  false,
		"exporter": "kafka",
	})); err != nil {
		t.Fatalf("Init(disabled, bad exporter): unexpected error: %v", err)
	}
}

// ── Init — OTLP endpoint validation ─────────────────────────────────────────

func TestInit_OTLP_EmptyEndpoint_Error(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":  true,
		"exporter": "otlp",
	})); err == nil {
		t.Fatal("Init(otlp, empty endpoint): expected error, got nil")
	}
}

func TestInit_OTLP_MalformedEndpoint_NoScheme(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":       true,
		"exporter":      "otlp",
		"otlp_endpoint": "not-a-url",
	})); err == nil {
		t.Fatal("Init(otlp, no-scheme): expected error, got nil")
	}
}

func TestInit_OTLP_MalformedEndpoint_NoHost(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{
		"enabled":       true,
		"exporter":      "otlp",
		"otlp_endpoint": "grpc://",
	})); err == nil {
		t.Fatal("Init(otlp, no-host): expected error, got nil")
	}
}

// ── Handler — disabled → transparent pass-through ────────────────────────────

func TestHandler_Disabled_PassThrough(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{"enabled": false})); err != nil {
		t.Fatal(err)
	}

	var called atomic.Int64
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	h := a.Handler(upstream)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status %d, want 200", i, rec.Code)
		}
	}
	if c := called.Load(); c != 5 {
		t.Errorf("upstream calls: got %d, want 5", c)
	}
	if n := lc.count(); n != 0 {
		t.Errorf("disabled plugin emitted %d log records, want 0", n)
	}
}

// ── Handler — stdout exporter ────────────────────────────────────────────────

func TestHandler_Stdout_EmitsLogPerRequest(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/campaigns",
		"", "corr-001", "req-001", "tenant-A", "user@example.com")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if rec := lc.last(); rec == nil {
		t.Fatal("stdout exporter: no log record emitted")
	} else if rec.message != spanName {
		t.Errorf("log message: got %q, want %q", rec.message, spanName)
	}
}

func TestHandler_Stdout_AllAuditEventFields(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/optimise",
		"", "corr-xyz", "req-xyz", "tenant-B", "alice")
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := lc.last()
	if rec == nil {
		t.Fatal("no log record captured")
	}

	// AuditEvent-aligned camelCase field names (sdk-go JSON schema)
	want := map[string]string{
		"eventType":     eventTypeValue,
		"tenantId":      "tenant-B",
		"actorId":       "alice",
		"operation":     "POST /v1/optimise",
		"correlationId": "corr-xyz",
		"requestId":     "req-xyz",
	}
	for k, v := range want {
		if got := rec.attrs[k]; got != v {
			t.Errorf("attr[%q]: got %q, want %q", k, got, v)
		}
	}
	if rec.attrs["timestamp"] == "" {
		t.Error("timestamp field must be present and non-empty")
	}
}

func TestHandler_Stdout_IncludeBodyFalse_BodyNotInLog(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/chat",
		"sensitive data", "c1", "r1", "t1", "actor1")
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := lc.last()
	if rec == nil {
		t.Fatal("no log record captured")
	}
	if _, ok := rec.attrs["requestBody"]; ok {
		t.Error("requestBody must NOT appear in log when include_request_body=false")
	}
}

func TestHandler_Stdout_IncludeBodyTrue_BodyInLog(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, true)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/chat",
		"hello world", "c2", "r2", "t2", "actor2")
	h.ServeHTTP(httptest.NewRecorder(), req)

	rec := lc.last()
	if rec == nil {
		t.Fatal("no log record captured")
	}
	if got := rec.attrs["requestBody"]; got != "hello world" {
		t.Errorf("requestBody: got %q, want %q", got, "hello world")
	}
}

func TestHandler_Stdout_IncludeBodyTrue_BodyRestoredForUpstream(t *testing.T) {
	a := newStdoutPlugin(t, true)
	var gotBody string
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		gotBody = string(data)
	})

	req := requestWithCtx(t, http.MethodPost, "/v1/chat",
		"payload text", "c3", "r3", "t3", "actor3")
	a.Handler(upstream).ServeHTTP(httptest.NewRecorder(), req)

	if gotBody != "payload text" {
		t.Errorf("upstream received body: got %q, want %q", gotBody, "payload text")
	}
}

func TestHandler_Stdout_MultipleRequests_OneLogEach(t *testing.T) {
	lc := &logCapture{}
	setLogger(t, lc)

	a := newStdoutPlugin(t, false)
	h := a.Handler(passThrough())

	for i := 0; i < 3; i++ {
		req := requestWithCtx(t, http.MethodGet, "/v1/ping",
			"", "c", "r", "t", "u")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if n := lc.count(); n != 3 {
		t.Errorf("log records: got %d, want 3", n)
	}
}

// ── Handler — OTLP exporter ───────────────────────────────────────────────────

func TestHandler_OTLP_SpanCreatedWithCorrectName(t *testing.T) {
	a, exp := newOTLPPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodGet, "/v1/status",
		"", "corr1", "req1", "tenant1", "actor1")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d, want 1", len(spans))
	}
	if got := spans[0].Name; got != spanName {
		t.Errorf("span name: got %q, want %q", got, spanName)
	}
}

func TestHandler_OTLP_AllFiveAttributes(t *testing.T) {
	a, exp := newOTLPPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/infer",
		"", "corr-A", "req-A", "tenant-X", "bob")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d, want 1", len(spans))
	}

	attrs := make(map[string]string)
	for _, kv := range spans[0].Attributes {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}

	want := map[string]string{
		"tenant_id":      "tenant-X",
		"actor_id":       "bob",
		"operation":      "POST /v1/infer",
		"correlation_id": "corr-A",
		"request_id":     "req-A",
	}
	for k, v := range want {
		if got := attrs[k]; got != v {
			t.Errorf("span attr[%q]: got %q, want %q", k, got, v)
		}
	}
}

func TestHandler_OTLP_IncludeBodyFalse_NoBodyAttribute(t *testing.T) {
	a, exp := newOTLPPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/chat",
		"secret body", "c", "r", "t", "u")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d, want 1", len(spans))
	}
	for _, kv := range spans[0].Attributes {
		if string(kv.Key) == "request_body" {
			t.Error("request_body must NOT appear in span when include_request_body=false")
		}
	}
}

func TestHandler_OTLP_IncludeBodyTrue_BodyInSpan(t *testing.T) {
	a, exp := newOTLPPlugin(t, true)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodPost, "/v1/chat",
		"the body content", "c", "r", "t", "u")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d, want 1", len(spans))
	}
	attrs := make(map[string]string)
	for _, kv := range spans[0].Attributes {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	if got := attrs["request_body"]; got != "the body content" {
		t.Errorf("request_body span attr: got %q, want %q", got, "the body content")
	}
}

func TestHandler_OTLP_SpanEnded(t *testing.T) {
	a, exp := newOTLPPlugin(t, false)
	h := a.Handler(passThrough())

	req := requestWithCtx(t, http.MethodGet, "/v1/health",
		"", "c", "r", "t", "u")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d, want 1", len(spans))
	}
	if spans[0].EndTime.IsZero() {
		t.Error("span must be ended (non-zero EndTime)")
	}
}

// ── Handler — context propagation ────────────────────────────────────────────

func TestHandler_ContextPropagated(t *testing.T) {
	a := newStdoutPlugin(t, false)

	type ctxKey struct{}
	var gotCtx context.Context
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotCtx = r.Context()
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "sentinel"))
	a.Handler(upstream).ServeHTTP(httptest.NewRecorder(), req)

	if gotCtx == nil {
		t.Fatal("context not propagated to upstream")
	}
	if gotCtx.Value(ctxKey{}) != "sentinel" {
		t.Error("original context values must survive plugin middleware")
	}
}

func TestHandler_OTLP_ContextPropagated(t *testing.T) {
	a, _ := newOTLPPlugin(t, false)

	type ctxKey struct{}
	var gotCtx context.Context
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotCtx = r.Context()
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "otlp-sentinel"))
	a.Handler(upstream).ServeHTTP(httptest.NewRecorder(), req)

	if gotCtx == nil {
		t.Fatal("context not propagated to upstream in OTLP mode")
	}
	if gotCtx.Value(ctxKey{}) != "otlp-sentinel" {
		t.Error("original context values must survive OTLP span injection")
	}
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

func TestShutdown_Stdout_NoError(t *testing.T) {
	a := newStdoutPlugin(t, false)
	if err := a.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(stdout): unexpected error: %v", err)
	}
}

func TestShutdown_OTLP_NoError(t *testing.T) {
	a, _ := newOTLPPlugin(t, false)
	if err := a.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(otlp): unexpected error: %v", err)
	}
}

func TestShutdown_Disabled_NoError(t *testing.T) {
	a := &OtelAudit{}
	if err := a.Init(plugin.NewMapConfig(map[string]any{"enabled": false})); err != nil {
		t.Fatal(err)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(disabled): unexpected error: %v", err)
	}
}
