package static

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// etagPlugin serves dir with etags of the requested strength.
func etagPlugin(t *testing.T, dir string, weak bool) http.Handler {
	t.Helper()

	h, _, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true, Weak: weak})

	return h
}

// writeFile writes content into dir and returns the request path for it.
func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))

	return "/" + name
}

// TestMiddlewareStrongEtagFollowsContent checks the strong validator comes from the bytes: a rewrite of the file must change it.
func TestMiddlewareStrongEtagFollowsContent(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "f.txt", "one")

	h := etagPlugin(t, dir, false)

	first := serveRequest(t, h, request(t, http.MethodGet, p)).etag()
	require.NotEmpty(t, first)
	require.False(t, strings.HasPrefix(first, "W/"), "a strong etag carries no W/ prefix, got %q", first)

	writeFile(t, dir, "f.txt", "a different body")

	second := serveRequest(t, h, request(t, http.MethodGet, p)).etag()
	require.NotEqual(t, first, second)
}

// TestMiddlewareStrongEtagSkipsEmptyFile covers the empty-body case: there is nothing to validate, so static emits no header.
func TestMiddlewareStrongEtagSkipsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "empty.txt", "")

	resp := serveRequest(t, etagPlugin(t, dir, false), request(t, http.MethodGet, p))

	require.Equal(t, http.StatusOK, resp.status)
	require.Empty(t, resp.etag())
}

// TestMiddlewareWeakEtag checks the weak form carries the prefix and tracks the file metadata.
func TestMiddlewareWeakEtag(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "f.txt", "one")

	h := etagPlugin(t, dir, true)

	first := serveRequest(t, h, request(t, http.MethodGet, p)).etag()
	require.True(t, strings.HasPrefix(first, `W/"`), "weak etag must carry the W/ prefix, got %q", first)

	writeFile(t, dir, "f.txt", "a different body")

	second := serveRequest(t, h, request(t, http.MethodGet, p)).etag()
	require.NotEqual(t, first, second, "the weak validator must follow size and mtime")
}

// TestMiddlewareOversizeFileHasNoStrongEtag covers the etagMaxSize cut-off in strong mode: a file too big to read into memory streams with no etag, so ServeContent keeps If-Range on Last-Modified.
func TestMiddlewareOversizeFileHasNoStrongEtag(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "big.bin")

	f, err := os.Create(name)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(etagMaxSize+1))
	require.NoError(t, f.Close())

	// HEAD keeps the 32MiB out of the response recorder
	resp := serveRequest(t, etagPlugin(t, dir, false), request(t, http.MethodHead, "/big.bin"))

	require.Equal(t, http.StatusOK, resp.status)
	require.Empty(t, resp.etag(), "a strong-mode file over etagMaxSize gets no etag, got %q", resp.etag())
}
