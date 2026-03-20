package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/roadrunner-server/config/v5"
	"github.com/roadrunner-server/static/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	mocklogger "tests/mock"
)

// newTestConfig creates a config.Plugin from in-memory YAML for testing.
func newTestConfig(t *testing.T, yamlContent string) *config.Plugin {
	t.Helper()

	cfg := &config.Plugin{
		ReadInCfg: []byte(yamlContent),
		Type:      "yaml",
		Version:   "2024.2.0",
	}
	require.NoError(t, cfg.Init())

	return cfg
}

func TestStaticFileServing(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{color:red}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0o600))

	cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    allow:
      - ".txt"
      - ".css"
    forbid:
      - ".js"
`)

	mockLog, oLogger := mocklogger.NewMockLogger(zapcore.DebugLevel)

	p := &static.Plugin{}
	require.NoError(t, p.Init(cfg, mockLog))

	// Track whether next handler is called
	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	t.Run("serves_allowed_txt_file", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/hello.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "hello world")
		assert.False(t, nextCalled.Load(), "next handler should not be called for allowed .txt file")
	})

	t.Run("serves_allowed_css_file", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/style.css", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "body{color:red}")
		assert.False(t, nextCalled.Load(), "next handler should not be called for allowed .css file")
	})

	t.Run("delegates_forbidden_js_file", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app.js", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled.Load(), "next handler should be called for forbidden .js file")
		assert.Greater(t, oLogger.FilterMessageSnippet("extension is forbidden").Len(), 0,
			"should log debug message about forbidden extension")
	})

	t.Run("delegates_no_extension", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/noext", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled.Load(), "next handler should be called for path without extension")
	})

	t.Run("delegates_missing_file", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/missing.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled.Load(), "next handler should be called for missing file")
		assert.Greater(t, oLogger.FilterMessageSnippet("no such file").Len(), 0,
			"should log debug message about missing file")
	})
}

func TestETagAndCustomHeaders(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello world"), 0o600))

	t.Run("strong_etag", func(t *testing.T) {
		cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    calculate_etag: true
    weak: false
`)

		mockLog, _ := mocklogger.NewMockLogger(zapcore.DebugLevel)
		p := &static.Plugin{}
		require.NoError(t, p.Init(cfg, mockLog))

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := p.Middleware(next)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		etagVal := rec.Header().Get("Etag")
		require.NotEmpty(t, etagVal, "Etag header must be set")
		assert.True(t, strings.HasPrefix(etagVal, `"`), "strong ETag should start with quote, got: %s", etagVal)
		assert.False(t, strings.HasPrefix(etagVal, `W/`), "strong ETag should not have W/ prefix, got: %s", etagVal)
	})

	t.Run("weak_etag", func(t *testing.T) {
		cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    calculate_etag: true
    weak: true
`)

		mockLog, _ := mocklogger.NewMockLogger(zapcore.DebugLevel)
		p := &static.Plugin{}
		require.NoError(t, p.Init(cfg, mockLog))

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := p.Middleware(next)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		etagVal := rec.Header().Get("Etag")
		require.NotEmpty(t, etagVal, "Etag header must be set")
		assert.True(t, strings.HasPrefix(etagVal, `W/"`), "weak ETag should start with W/\", got: %s", etagVal)
	})

	t.Run("custom_response_headers", func(t *testing.T) {
		cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    response:
      X-Custom: "test-value"
`)

		mockLog, _ := mocklogger.NewMockLogger(zapcore.DebugLevel)
		p := &static.Plugin{}
		require.NoError(t, p.Init(cfg, mockLog))

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := p.Middleware(next)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "test-value", rec.Header().Get("X-Custom"))
	})

	t.Run("custom_request_headers", func(t *testing.T) {
		cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    request:
      X-Request-ID: "static-asset"
`)

		mockLog, _ := mocklogger.NewMockLogger(zapcore.DebugLevel)
		p := &static.Plugin{}
		require.NoError(t, p.Init(cfg, mockLog))

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := p.Middleware(next)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		// The middleware adds request headers to the original request before serving
		assert.Equal(t, "static-asset", req.Header.Get("X-Request-ID"),
			"request header should be injected by middleware")
	})

	t.Run("etag_determinism", func(t *testing.T) {
		cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    calculate_etag: true
    weak: false
`)

		mockLog, _ := mocklogger.NewMockLogger(zapcore.DebugLevel)
		p := &static.Plugin{}
		require.NoError(t, p.Init(cfg, mockLog))

		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := p.Middleware(next)

		// First request
		req1 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)

		// Second request
		req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test.txt", nil)
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)

		etag1 := rec1.Header().Get("Etag")
		etag2 := rec2.Header().Get("Etag")

		require.NotEmpty(t, etag1)
		assert.Equal(t, etag1, etag2, "ETag should be deterministic for the same file content")
	})
}

func TestPathTraversalAndDirectoryProtection(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("safe content"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o755))

	cfg := newTestConfig(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    allow:
      - ".txt"
`)

	mockLog, oLogger := mocklogger.NewMockLogger(zapcore.DebugLevel)

	p := &static.Plugin{}
	require.NoError(t, p.Init(cfg, mockLog))

	var nextCalled atomic.Bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	t.Run("blocks_path_traversal", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/../etc/passwd.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code, "path traversal should return 403")
		assert.False(t, nextCalled.Load(), "next handler should not be called for path traversal")
	})

	t.Run("delegates_directory_access", func(t *testing.T) {
		nextCalled.Store(false)

		// Create a file inside subdir to ensure Open succeeds but it's a directory
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/subdir", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// /subdir has no extension, so it delegates to next handler
		assert.True(t, nextCalled.Load(), "next handler should be called for directory path")
	})

	t.Run("serves_safe_file", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/safe.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "safe content")
		assert.False(t, nextCalled.Load(), "next handler should not be called for safe file")
	})

	t.Run("blocks_dotdot_in_path", func(t *testing.T) {
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/subdir/../../../etc/hosts.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code, "path with .. should return 403")
		assert.False(t, nextCalled.Load(), "next handler should not be called for path with ..")
	})

	// Verify warn log for directory access attempt with extension
	t.Run("warns_on_directory_with_extension", func(t *testing.T) {
		// Create a directory with a .txt extension to trigger the warn log
		dirWithExt := filepath.Join(dir, "fakefile.txt")
		require.NoError(t, os.MkdirAll(dirWithExt, 0o755))
		nextCalled.Store(false)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fakefile.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled.Load(), "next handler should be called when path is a directory")
		assert.Greater(t, oLogger.FilterMessageSnippet("path to dir provided").Len(), 0,
			"should log warn message about directory access")
	})
}
