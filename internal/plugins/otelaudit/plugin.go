// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 AimpathyMinds

// Package otelaudit implements the otel-audit gateway plugin (PRD §6.2.5).
//
// The plugin emits one audit record per gateway-proxied request:
//   - Exporter "stdout" (default): a structured slog INFO record whose field
//     names mirror the sdk-go AuditEvent JSON schema, enabling DOC-05 to
//     document one consistent contract across SDK and gateway.
//   - Exporter "otlp": an OpenTelemetry span exported via gRPC OTLP.
//
// Registration: init() calls plugin.Register so the gateway wires this plugin
// by import side-effect.
package otelaudit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/ai-mpathyminds/yaagents-gateway/internal/reqctx"
	"github.com/ai-mpathyminds/yaagents-gateway/plugin"
)

const (
	pluginName     = "otel-audit"
	spanName       = "agentic.request"
	eventTypeValue = "agentic.request.received"
	maxBodyBytes   = int64(1 << 20) // 1 MiB
)

func init() {
	plugin.Register(&OtelAudit{})
}

// OtelAudit is the otel-audit gateway plugin.
// Zero value is invalid; always call Init before Handler.
type OtelAudit struct {
	enabled        bool
	exporterType   string // "stdout" or "otlp"
	otlpEndpoint   string
	includeReqBody bool

	tp         *sdktrace.TracerProvider // non-nil for OTLP mode
	tracer     oteltrace.Tracer
	shutdownFn func(context.Context) error
}

// Name returns the canonical plugin identifier.
func (a *OtelAudit) Name() string { return pluginName }

// Init validates configuration and sets up the chosen exporter.
//
// Returns a non-nil error when:
//   - exporter is "otlp" and otlp_endpoint is empty or not a valid absolute URL.
//   - exporter value is unrecognised.
func (a *OtelAudit) Init(cfg plugin.PluginConfig) error {
	a.enabled = cfg.GetBool("enabled")
	a.exporterType = cfg.GetString("exporter")
	if a.exporterType == "" {
		a.exporterType = "stdout"
	}
	a.otlpEndpoint = cfg.GetString("otlp_endpoint")
	a.includeReqBody = cfg.GetBool("include_request_body")

	if !a.enabled {
		a.tracer = nooptrace.NewTracerProvider().Tracer(pluginName)
		a.shutdownFn = func(context.Context) error { return nil }
		return nil
	}

	switch a.exporterType {
	case "stdout":
		// Stdout exporter: structured JSON via slog; no OTel SDK needed.
		a.tracer = nooptrace.NewTracerProvider().Tracer(pluginName)
		a.shutdownFn = func(context.Context) error { return nil }
		return nil

	case "otlp":
		if a.otlpEndpoint == "" {
			return fmt.Errorf("otel-audit: exporter=otlp requires otlp_endpoint to be set")
		}
		u, err := url.Parse(a.otlpEndpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("otel-audit: otlp_endpoint %q must be a valid absolute URL (e.g. http://otel-collector:4317)", a.otlpEndpoint)
		}
		exp, err := otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(u.Host),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("otel-audit: OTLP exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
		a.tp = tp
		a.tracer = tp.Tracer(pluginName)
		a.shutdownFn = tp.Shutdown
		return nil

	default:
		return fmt.Errorf("otel-audit: unknown exporter %q (want: stdout, otlp)", a.exporterType)
	}
}

// initWithExporter wires a TracerProvider with the given span exporter using
// synchronous export (SimpleSpanProcessor). Intended for test injection:
//
//	exp := tracetest.NewInMemoryExporter()
//	if err := a.initWithExporter(exp); err != nil { … }
//
// Production OTLP export uses a BatchSpanProcessor wired directly in Init.
func (a *OtelAudit) initWithExporter(exp sdktrace.SpanExporter) error {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	a.tp = tp
	a.tracer = tp.Tracer(pluginName)
	a.shutdownFn = tp.Shutdown
	return nil
}

// Handler returns a middleware that emits one audit record per request.
//
// Stdout exporter: emits a slog INFO record with AuditEvent-aligned JSON field
// names (eventType, tenantId, actorId, operation, correlationId, requestId,
// timestamp). OTLP exporter: creates and ends an OTel span named
// "agentic.request" carrying five standard attributes.
//
// When disabled, the handler is a transparent pass-through.
func (a *OtelAudit) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		corrID := reqctx.CorrelationID(ctx)
		reqID := reqctx.RequestID(ctx)
		tenantID := reqctx.TenantID(ctx)
		actor := reqctx.ActorSubject(ctx)
		operation := r.Method + " " + r.URL.Path

		var body string
		if a.includeReqBody && r.Body != nil {
			data, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
			body = string(data)
			r.Body = io.NopCloser(strings.NewReader(body))
		}

		switch a.exporterType {
		case "stdout":
			a.emitStdoutLog(ctx, tenantID, actor, operation, corrID, reqID, body)
			next.ServeHTTP(w, r)

		case "otlp":
			spanCtx, span := a.tracer.Start(ctx, spanName)
			span.SetAttributes(
				attribute.String("tenant_id", tenantID),
				attribute.String("actor_id", actor),
				attribute.String("operation", operation),
				attribute.String("correlation_id", corrID),
				attribute.String("request_id", reqID),
			)
			if body != "" {
				span.SetAttributes(attribute.String("request_body", body))
			}
			next.ServeHTTP(w, r.WithContext(spanCtx))
			span.End()

		default:
			// Defensive pass-through; should never occur if Init was called.
			next.ServeHTTP(w, r)
		}
	})
}

// emitStdoutLog writes a slog INFO record with AuditEvent-aligned JSON field
// names. Field names mirror sdk-go AuditEvent JSON tags so that the DOC-05
// audit-and-observability page can document one consistent contract across SDK
// and gateway (per INTAKE-5 coupling + ADR PI4-yaa-0001 §6.2.5).
func (a *OtelAudit) emitStdoutLog(ctx context.Context, tenantID, actor, operation, corrID, reqID, body string) {
	attrs := []slog.Attr{
		slog.String("eventType", eventTypeValue),
		slog.String("tenantId", tenantID),
		slog.String("actorId", actor),
		slog.String("operation", operation),
		slog.String("correlationId", corrID),
		slog.String("requestId", reqID),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339Nano)),
	}
	if body != "" {
		attrs = append(attrs, slog.String("requestBody", body))
	}
	slog.LogAttrs(ctx, slog.LevelInfo, spanName, attrs...)
}

// Shutdown flushes pending spans and releases exporter resources.
// For the stdout exporter this is a no-op; for OTLP it triggers a final batch
// flush before the process exits.
func (a *OtelAudit) Shutdown(ctx context.Context) error {
	if a.shutdownFn != nil {
		return a.shutdownFn(ctx)
	}
	return nil
}
