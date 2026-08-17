package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// openFile writes content into a temp dir and opens it through http.Dir, which
// is what the plugin hands SetEtag at runtime.
func openFile(t *testing.T, content string) http.File {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte(content), 0o600))

	f, err := http.Dir(dir).Open("/f.txt")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	return f
}

// TestSetEtagWeakUsesNameNotContent checks the weak form is derived from the
// file name, so two files with different content share an etag.
func TestSetEtagWeakUsesNameNotContent(t *testing.T) {
	first := httptest.NewRecorder()
	SetEtag(true, openFile(t, "one"), "same-name.txt", first)

	second := httptest.NewRecorder()
	SetEtag(true, openFile(t, "a different body"), "same-name.txt", second)

	got := first.Header().Get("Etag")
	require.NotEmpty(t, got)
	require.True(t, len(got) > 2 && got[:2] == "W/", "weak etag must carry the W/ prefix, got %q", got)
	require.Equal(t, got, second.Header().Get("Etag"))
}

// TestSetEtagStrongUsesContent checks the strong form changes with the body.
func TestSetEtagStrongUsesContent(t *testing.T) {
	first := httptest.NewRecorder()
	SetEtag(false, openFile(t, "one"), "f.txt", first)

	second := httptest.NewRecorder()
	SetEtag(false, openFile(t, "another"), "f.txt", second)

	require.NotEmpty(t, first.Header().Get("Etag"))
	require.NotEqual(t, first.Header().Get("Etag"), second.Header().Get("Etag"))
}

// TestSetEtagSkipsEmptyBody covers the early return: an empty file gets no etag
// at all rather than an etag over zero bytes.
func TestSetEtagSkipsEmptyBody(t *testing.T) {
	rec := httptest.NewRecorder()

	SetEtag(false, openFile(t, ""), "empty.txt", rec)

	require.Empty(t, rec.Header().Get("Etag"))
}
