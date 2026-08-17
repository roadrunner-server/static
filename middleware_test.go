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

// servePlugin builds a plugin over dir with the given allow/forbid lists and
// returns its middleware plus a flag reporting whether the request fell through
// to the next handler.
func servePlugin(t *testing.T, dir string, allow, forbid []string) (http.Handler, *atomic.Bool) {
	t.Helper()

	p := &Plugin{}
	c := &stubConfigurer{
		sections: bothSections(),
		cfg:      &Config{Dir: dir, Allow: allow, Forbid: forbid},
	}
	require.NoError(t, p.Init(c, discardLogger{}))

	var fellThrough atomic.Bool
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fellThrough.Store(true)
		w.WriteHeader(http.StatusTeapot)
	}))

	return h, &fellThrough
}

// requestPath drives one request through the middleware and returns the status
// the recorder captured, so no response body is left open.
func requestPath(t *testing.T, h http.Handler, path string) int {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))

	resp := rec.Result()
	require.NoError(t, resp.Body.Close())

	return resp.StatusCode
}

// TestExtensionOutsideAllowListFallsThrough covers the branch where an allow
// list exists and the requested extension is not on it: static declines and the
// worker handles the request.
func TestExtensionOutsideAllowListFallsThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "image.png"), []byte("not-really-a-png"), 0o600))

	h, fellThrough := servePlugin(t, dir, []string{".txt"}, nil)

	status := requestPath(t, h, "/image.png")

	require.True(t, fellThrough.Load(), "request should have reached the worker")
	require.Equal(t, http.StatusTeapot, status)
}

// TestDirectoryRequestFallsThrough covers the IsDir branch: a path pointing at a
// directory is never served, it goes to the worker.
func TestDirectoryRequestFallsThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))

	h, fellThrough := servePlugin(t, dir, nil, nil)

	status := requestPath(t, h, "/assets")

	require.True(t, fellThrough.Load(), "a directory must not be served")
	require.Equal(t, http.StatusTeapot, status)
}

// TestAllowedExtensionIsServed is the positive counterpart: the file is written
// by static and never reaches the worker.
func TestAllowedExtensionIsServed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world"), 0o600))

	h, fellThrough := servePlugin(t, dir, []string{".txt"}, nil)

	status := requestPath(t, h, "/hello.txt")

	require.False(t, fellThrough.Load(), "static should have served the file itself")
	require.Equal(t, http.StatusOK, status)
}
