package static

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
)

func TestMiddlewareSpanEndsBeforeNextHandler(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	dir := t.TempDir()

	p := &Plugin{
		cfg:                 &Config{Dir: dir},
		log:                 zap.NewNop(),
		root:                http.Dir(dir),
		allowedExtensions:   make(map[string]struct{}),
		forbiddenExtensions: make(map[string]struct{}),
		prop:                propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	}

	// "next" handler that creates its own span to mark when downstream starts
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, span := tp.Tracer("test").Start(r.Context(), "nextHandler")
		defer span.End()
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	// Create a parent span so the middleware finds a TracerProvider in context
	ctx, parentSpan := tp.Tracer("test").Start(t.Context(), "parent")
	defer parentSpan.End()

	// Set OtelTracerNameKey so the middleware activates its OTEL branch
	ctx = context.WithValue(ctx, rrcontext.OtelTracerNameKey, "test-tracer")

	// Request without file extension — delegates to next handler
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/noext", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Flush and collect spans
	require.NoError(t, tp.ForceFlush(t.Context()))

	spans := exporter.GetSpans()

	var staticSpan, nextSpan tracetest.SpanStub
	for _, s := range spans {
		switch s.Name {
		case PluginName:
			staticSpan = s
		case "nextHandler":
			nextSpan = s
		}
	}

	require.NotEmpty(t, staticSpan.Name, "static middleware span was not found in exported spans")
	require.NotEmpty(t, nextSpan.Name, "next handler span was not found in exported spans")
	require.NotZero(t, staticSpan.EndTime, "static span should have ended")
	require.NotZero(t, nextSpan.StartTime, "next handler span should have started")

	assert.True(t,
		!staticSpan.EndTime.After(nextSpan.StartTime),
		"static span must end before (or at) the next handler span starts: static.End=%v, next.Start=%v",
		staticSpan.EndTime, nextSpan.StartTime,
	)
}

func TestMiddlewareSpanEndsAfterServingFile(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o600))

	p := &Plugin{
		cfg:                 &Config{Dir: dir},
		log:                 zap.NewNop(),
		root:                http.Dir(dir),
		allowedExtensions:   make(map[string]struct{}),
		forbiddenExtensions: make(map[string]struct{}),
		prop:                propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	// Create a parent span so the middleware finds a TracerProvider in context
	ctx, parentSpan := tp.Tracer("test").Start(t.Context(), "parent")
	defer parentSpan.End()

	ctx = context.WithValue(ctx, rrcontext.OtelTracerNameKey, "test-tracer")

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/hello.txt", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, nextCalled, "next handler should not have been called for a served static file")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "hello world")

	// Flush and collect spans
	require.NoError(t, tp.ForceFlush(t.Context()))

	spans := exporter.GetSpans()

	var staticSpan tracetest.SpanStub
	for _, s := range spans {
		if s.Name == PluginName {
			staticSpan = s
		}
	}

	require.NotEmpty(t, staticSpan.Name, "static middleware span was not found in exported spans")
	require.NotZero(t, staticSpan.EndTime, "static span should have ended after serving the file")
}
