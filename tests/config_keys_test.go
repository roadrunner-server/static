package static

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mocklogger "tests/mock"

	"github.com/roadrunner-server/static/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticHandler is a configured middleware and the state its next handler shows to assertions.
type staticHandler struct {
	handler http.Handler
	// fellThrough reports whether the last request reached the next handler.
	fellThrough *atomic.Bool
	logs        *mocklogger.ObservedLogs
}

// newStaticHandler starts the plugin from YAML; the next handler answers StatusTeapot to mark fall-through.
func newStaticHandler(t *testing.T, yamlContent string) *staticHandler {
	t.Helper()

	mockLog, logs := mocklogger.NewMockLogger(slog.LevelDebug)

	p := &static.Plugin{}
	require.NoError(t, p.Init(newTestConfig(t, yamlContent), mockLog))

	sh := &staticHandler{fellThrough: new(atomic.Bool), logs: logs}
	sh.handler = p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sh.fellThrough.Store(true)
		w.WriteHeader(http.StatusTeapot)
	}))

	return sh
}

// do drives one request through the middleware.
func (sh *staticHandler) do(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	sh.fellThrough.Store(false)

	rec := httptest.NewRecorder()
	sh.handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))

	return rec
}

func (sh *staticHandler) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()

	return sh.do(t, http.MethodGet, path)
}

// initError returns the Init error for a config that must be rejected.
func initError(t *testing.T, yamlContent string) error {
	t.Helper()

	mockLog, _ := mocklogger.NewMockLogger(slog.LevelDebug)

	return (&static.Plugin{}).Init(newTestConfig(t, yamlContent), mockLog)
}

// TestPrefixesAndCacheKeysFromYAML checks the cache settings and prefixes decode from YAML and limit serving.
func TestPrefixesAndCacheKeysFromYAML(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app.css"), []byte("body{color:red}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outside.css"), []byte("body{color:blue}"), 0o600))

	sh := newStaticHandler(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    prefixes:
      - "/assets/"
    cache_ttl: 50ms
    cache_miss_ttl: 50ms
    cache_max_entries: 128
`)

	t.Run("inside_prefix_is_served", func(t *testing.T) {
		rec := sh.get(t, "/assets/app.css")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "body{color:red}", rec.Body.String())
		assert.False(t, sh.fellThrough.Load(), "a path under the prefix belongs to static")
	})

	t.Run("outside_prefix_falls_through", func(t *testing.T) {
		rec := sh.get(t, "/outside.css")

		require.Equal(t, http.StatusTeapot, rec.Code)
		assert.True(t, sh.fellThrough.Load(), "a path outside every prefix belongs to the worker")
	})
}

// TestZeroTTLsDisableCaching checks a zero TTL does not cache a miss, so a new file is served at once.
func TestZeroTTLsDisableCaching(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "late.css")

	sh := newStaticHandler(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    cache_ttl: 0s
    cache_miss_ttl: 0s
`)

	require.Equal(t, http.StatusTeapot, sh.get(t, "/late.css").Code, "the file does not exist yet")
	require.True(t, sh.fellThrough.Load())

	require.NoError(t, os.WriteFile(file, []byte("body{color:green}"), 0o600))

	rec := sh.get(t, "/late.css")

	require.Equal(t, http.StatusOK, rec.Code, "an uncached miss must not survive the file appearing")
	assert.Equal(t, "body{color:green}", rec.Body.String())
	assert.False(t, sh.fellThrough.Load())
}

// TestCacheMissTTLFromYAML checks the miss cache TTL holds a miss until it expires, then serves the file.
func TestCacheMissTTLFromYAML(t *testing.T) {
	const missTTL = 100 * time.Millisecond

	dir := t.TempDir()
	file := filepath.Join(dir, "appears.css")

	sh := newStaticHandler(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    cache_miss_ttl: `+missTTL.String()+`
`)

	require.Equal(t, http.StatusTeapot, sh.get(t, "/appears.css").Code, "the file does not exist yet")
	misses := sh.logs.FilterMessageSnippet("file open error").Len()
	require.Positive(t, misses, "the first miss goes through the filesystem")

	require.NoError(t, os.WriteFile(file, []byte("body{color:green}"), 0o600))

	rec := sh.get(t, "/appears.css")
	require.Equal(t, http.StatusTeapot, rec.Code, "the remembered miss hides the new file until it expires")
	assert.True(t, sh.fellThrough.Load())
	assert.Equal(t, misses, sh.logs.FilterMessageSnippet("file open error").Len(),
		"a cached miss must not reopen the file")

	time.Sleep(missTTL + 50*time.Millisecond)

	rec = sh.get(t, "/appears.css")

	require.Equal(t, http.StatusOK, rec.Code, "the file must be served once the miss expires")
	assert.Equal(t, "body{color:green}", rec.Body.String())
	assert.False(t, sh.fellThrough.Load())
}

// TestWeakEtagFromYAML checks the weak validator shape and that a changed file gets a new validator.
func TestWeakEtagFromYAML(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "logo.css")

	past := time.Now().Add(-time.Hour)
	require.NoError(t, os.WriteFile(file, []byte("body{color:red}"), 0o600))
	require.NoError(t, os.Chtimes(file, past, past))

	sh := newStaticHandler(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    calculate_etag: true
    weak: true
`)

	first := sh.get(t, "/logo.css")
	require.Equal(t, http.StatusOK, first.Code)

	firstEtag := first.Header().Get("Etag")
	require.NotEmpty(t, firstEtag)
	require.True(t, strings.HasPrefix(firstEtag, `W/"`), "weak etag should start with W/\", got: %s", firstEtag)

	// a different size and mtime, so the metadata validator must change
	newer := past.Add(30 * time.Minute)
	require.NoError(t, os.WriteFile(file, []byte("body{color:blue}\n"), 0o600))
	require.NoError(t, os.Chtimes(file, newer, newer))

	second := sh.get(t, "/logo.css")
	require.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, "body{color:blue}\n", second.Body.String(), "the new content must be served")

	secondEtag := second.Header().Get("Etag")
	require.True(t, strings.HasPrefix(secondEtag, `W/"`), "weak etag should start with W/\", got: %s", secondEtag)
	assert.NotEqual(t, firstEtag, secondEtag, "a changed file must get a new validator")
}

// TestInvalidConfigRejected covers config errors from YAML: negative TTL, negative cap, prefix without '/'.
func TestInvalidConfigRejected(t *testing.T) {
	dir := t.TempDir()

	t.Run("negative_cache_ttl", func(t *testing.T) {
		err := initError(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    cache_ttl: -1s
`)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache_ttl must not be negative")
	})

	t.Run("negative_cache_max_entries", func(t *testing.T) {
		err := initError(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    cache_max_entries: -1
`)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cache_max_entries must not be negative")
	})

	t.Run("prefix_without_leading_slash", func(t *testing.T) {
		err := initError(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    prefixes:
      - "assets/"
`)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "prefix should start with '/'")
		assert.Contains(t, err.Error(), "assets/", "the offending prefix must be named")
	})
}

// TestReadMethodsOnly covers the method check: HEAD gets headers but no body, writes go to the worker.
func TestReadMethodsOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "head.css"), []byte("body{color:red}"), 0o600))

	sh := newStaticHandler(t, `
version: "3"
http:
  static:
    dir: "`+dir+`"
    calculate_etag: true
`)

	t.Run("head_is_served_without_a_body", func(t *testing.T) {
		rec := sh.do(t, http.MethodHead, "/head.css")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.False(t, sh.fellThrough.Load(), "HEAD is a read, static answers it")
		assert.Empty(t, rec.Body.String(), "a HEAD response carries no body")
		assert.Equal(t, "15", rec.Header().Get("Content-Length"), "the headers describe the whole entity")
		assert.NotEmpty(t, rec.Header().Get("Etag"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
	})

	t.Run("post_falls_through", func(t *testing.T) {
		rec := sh.do(t, http.MethodPost, "/head.css")

		require.Equal(t, http.StatusTeapot, rec.Code)
		assert.True(t, sh.fellThrough.Load(), "a write belongs to the worker even when the file exists")
	})
}
