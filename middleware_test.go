package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// servePlugin builds a plugin over dir with allow/forbid lists. It returns the middleware and a fall-through flag.
func servePlugin(t *testing.T, dir string, allow, forbid []string) (http.Handler, *atomic.Bool) {
	t.Helper()

	h, _, fellThrough := servePluginCfg(t, &Config{Dir: dir, Allow: allow, Forbid: forbid})

	return h, fellThrough
}

// servePluginCfg is servePlugin over any config. It also returns the plugin so a test can reach the cache state.
func servePluginCfg(t testing.TB, cfg *Config) (http.Handler, *Plugin, *atomic.Bool) {
	t.Helper()

	p := &Plugin{}
	require.NoError(t, p.Init(&stubConfigurer{sections: bothSections(), cfg: cfg}, discardLogger{}))

	var fellThrough atomic.Bool
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fellThrough.Store(true)
		w.WriteHeader(http.StatusTeapot)
	}))

	return h, p, &fellThrough
}

// response holds the result of one trip through the middleware.
type response struct {
	status int
	header http.Header
	body   string
}

func (r response) etag() string {
	return r.header.Get(etag)
}

// requestPath drives one GET through the middleware and returns the status.
func requestPath(t testing.TB, h http.Handler, path string) int {
	t.Helper()

	return serveRequest(t, h, request(t, http.MethodGet, path)).status
}

// request builds a request to drive the middleware.
func request(t testing.TB, method, path string) *http.Request {
	t.Helper()

	return httptest.NewRequestWithContext(t.Context(), method, path, nil)
}

// serveRequest drives one request through the middleware.
func serveRequest(t testing.TB, h http.Handler, req *http.Request) response {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return response{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
}

// responseBody drives a GET and returns status plus body.
func responseBody(t testing.TB, h http.Handler, path string) (int, string) {
	t.Helper()

	resp := serveRequest(t, h, request(t, http.MethodGet, path))

	return resp.status, resp.body
}

// TestExtensionOutsideAllowListFallsThrough covers the allow-list branch: the extension is not listed, so static declines and the worker handles the request.
func TestExtensionOutsideAllowListFallsThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte("not-really-a-png"), 0o600))

	h, fellThrough := servePlugin(t, dir, []string{".txt"}, nil)

	status := requestPath(t, h, "/image.png")

	require.True(t, fellThrough.Load(), "request should have reached the worker")
	require.Equal(t, http.StatusTeapot, status)
}

// TestForbiddenExtensionFallsThrough covers the forbid list: static declines the extension before it opens the file.
func TestForbiddenExtensionFallsThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0o600))

	h, fellThrough := servePlugin(t, dir, nil, []string{".js"})

	status := requestPath(t, h, "/app.js")

	require.True(t, fellThrough.Load(), "a forbidden extension belongs to the worker")
	require.Equal(t, http.StatusTeapot, status)
}

// TestDirectoryRequestFallsThrough covers the IsDir branch: static never serves a directory, so it falls through and the cache remembers the miss.
func TestDirectoryRequestFallsThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.txt"), 0o750))

	h, p, fellThrough := servePluginCfg(t, &Config{Dir: dir, Allow: []string{".txt"}})

	status := requestPath(t, h, "/sub.txt")

	require.True(t, fellThrough.Load(), "a directory must not be served")
	require.Equal(t, http.StatusTeapot, status)
	require.True(t, p.cache.Load().lookupNegative("/sub.txt"), "a directory is remembered as a miss")
}

// TestAllowedExtensionIsServed is the positive counterpart: static writes the file and it never reaches the worker.
func TestAllowedExtensionIsServed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o600))

	h, fellThrough := servePlugin(t, dir, []string{".txt"}, nil)

	status := requestPath(t, h, "/hello.txt")

	require.False(t, fellThrough.Load(), "static should have served the file itself")
	require.Equal(t, http.StatusOK, status)
}
