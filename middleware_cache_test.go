package static

import (
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// countingFS counts the filesystem work the middleware does, so a test can tell a cached answer from a disk read.
type countingFS struct {
	inner http.FileSystem
	opens atomic.Int64
	stats atomic.Int64
	reads atomic.Int64
}

func (c *countingFS) Open(name string) (http.File, error) {
	c.opens.Add(1)

	f, err := c.inner.Open(name)
	if err != nil {
		return nil, err
	}

	return &countingFile{File: f, fs: c}, nil
}

type countingFile struct {
	http.File
	fs *countingFS
}

func (f *countingFile) Stat() (fs.FileInfo, error) {
	f.fs.stats.Add(1)

	return f.File.Stat()
}

func (f *countingFile) Read(p []byte) (int, error) {
	f.fs.reads.Add(1)

	return f.File.Read(p)
}

// errFS fails every open with a fixed error.
type errFS struct{ err error }

func (e errFS) Open(string) (http.File, error) { return nil, e.err }

// countingRoot swaps the plugin filesystem for a counting wrapper.
func countingRoot(p *Plugin) *countingFS {
	c := &countingFS{inner: p.root}
	p.root = c

	return c
}

// backdate pushes the file mtime past the settle window, so the middleware can cache it.
func backdate(t testing.TB, name string) {
	t.Helper()

	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(name, old, old))
}

// writeAged writes a file the middleware may cache right away and returns its request path.
func writeAged(t testing.TB, dir, name, content string) string {
	t.Helper()

	p := writeFile(t, dir, name, content)
	backdate(t, filepath.Join(dir, name))

	return p
}

// TestNonReadMethodFallsThrough pins the method gate: a POST to an existing static path belongs to the worker.
func TestNonReadMethodFallsThrough(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "hello.txt", "hello world")

	h, fellThrough := servePlugin(t, dir, nil, nil)

	resp := serveRequest(t, h, request(t, http.MethodPost, p))

	require.True(t, fellThrough.Load(), "POST must reach the worker")
	require.Equal(t, http.StatusTeapot, resp.status)
}

// TestDotDotSegmentsAreCanonicalized covers the traversal gate: path.Clean resolves every ".." segment, so a traversal attempt falls through while a dotted file name stays legal.
func TestDotDotSegmentsAreCanonicalized(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app..min.js"), []byte("var a=1"), 0o600))

	h, fellThrough := servePlugin(t, dir, nil, nil)

	require.Equal(t, http.StatusOK, requestPath(t, h, "/assets/app..min.js"))
	require.False(t, fellThrough.Load(), "a file with dots in its name must be served")

	fellThrough.Store(false)
	require.Equal(t, http.StatusTeapot, requestPath(t, h, "/../etc/passwd.txt"),
		"a traversal attempt is canonicalized and falls through")
	require.True(t, fellThrough.Load())

	fellThrough.Store(false)
	require.Equal(t, http.StatusTeapot, requestPath(t, h, `/assets\..\secret.txt`),
		"a backslash traversal resolves to a name that does not exist and falls through")
	require.True(t, fellThrough.Load())
}

// TestPrefixGate covers the prefix allow list: static declines a path outside every prefix before it touches the filesystem.
func TestPrefixGate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("var a=1"), 0o600))
	writeFile(t, dir, "hello.txt", "hello world")

	h, p, fellThrough := servePluginCfg(t, &Config{Dir: dir, Prefixes: []string{"/assets/"}})
	c := countingRoot(p)

	require.Equal(t, http.StatusTeapot, requestPath(t, h, "/hello.txt"))
	require.True(t, fellThrough.Load(), "a path outside the prefixes goes to the worker")
	require.Zero(t, c.opens.Load(), "a path outside the prefixes must not reach the filesystem")

	fellThrough.Store(false)
	status, body := responseBody(t, h, "/assets/app.js")

	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "var a=1", body)
	require.False(t, fellThrough.Load())
}

// TestCanonicalizationGatesSmuggledPath pins the gate on the canonical path: a control character cannot collapse into a ".." segment, so a smuggled path falls through.
func TestCanonicalizationGatesSmuggledPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app..min.js"), []byte("var a=1"), 0o600))
	writeFile(t, dir, "secret.txt", "top secret")

	h, _, fellThrough := servePluginCfg(t, &Config{Dir: dir, Prefixes: []string{"/assets/"}})

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/assets/\r../secret.txt"},
		Header: make(http.Header),
	}

	resp := serveRequest(t, h, req.WithContext(t.Context()))

	require.Equal(t, http.StatusTeapot, resp.status)
	require.NotContains(t, resp.body, "top secret")
	require.True(t, fellThrough.Load(), "the smuggled path is never served")

	status, body := responseBody(t, h, "/assets/app..min.js")

	require.Equal(t, http.StatusOK, status, "a file with dots in its name is not a traversal")
	require.Equal(t, "var a=1", body)
}

// TestNegativeCacheSkipsFilesystem covers the miss cache: a repeat request for an absent path costs no syscall until the entry ages out.
func TestNegativeCacheSkipsFilesystem(t *testing.T) {
	dir := t.TempDir()

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CacheMissTTL: new(50 * time.Millisecond)})
	c := countingRoot(p)

	require.Equal(t, http.StatusTeapot, requestPath(t, h, "/missing.txt"))
	require.EqualValues(t, 1, c.opens.Load())

	require.Equal(t, http.StatusTeapot, requestPath(t, h, "/missing.txt"))
	require.EqualValues(t, 1, c.opens.Load(), "a warm negative entry answers without a syscall")

	time.Sleep(80 * time.Millisecond)
	writeFile(t, dir, "missing.txt", "now here")

	status, body := responseBody(t, h, "/missing.txt")

	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "now here", body)
}

// TestDeletedFileFallsThroughImmediately covers the verified-hit path for a deleted file: the stale entry is dropped and the miss recorded, with no wait for the positive ttl.
func TestDeletedFileFallsThroughImmediately(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeAged(t, dir, "gone.txt", "content")

	h, p, fellThrough := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	require.Equal(t, http.StatusOK, requestPath(t, h, reqPath))
	require.NotNil(t, p.cache.Load().lookupPositive(reqPath), "a settled file must be cached")

	require.NoError(t, os.Remove(filepath.Join(dir, "gone.txt")))
	fellThrough.Store(false)

	require.Equal(t, http.StatusTeapot, requestPath(t, h, reqPath))
	require.True(t, fellThrough.Load(), "a deleted file goes to the worker at once")
	require.Nil(t, p.cache.Load().lookupPositive(reqPath), "the stale entry must be dropped")
	require.True(t, p.cache.Load().lookupNegative(reqPath), "the miss must be recorded")
}

// TestReplacedFileServesNewBytes covers the fstat mismatch: the cached entry no longer describes the file, so it is refilled from disk.
func TestReplacedFileServesNewBytes(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeAged(t, dir, "a.txt", "first")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	resp := serveRequest(t, h, request(t, http.MethodGet, reqPath))
	first := resp.etag()

	require.Equal(t, "first", resp.body)
	require.NotEmpty(t, first)
	require.NotNil(t, p.cache.Load().lookupPositive(reqPath))

	writeAged(t, dir, "a.txt", "second body, longer")

	resp = serveRequest(t, h, request(t, http.MethodGet, reqPath))

	require.Equal(t, "second body, longer", resp.body)
	require.NotEqual(t, first, resp.etag(), "the validator must follow the new bytes")

	e := p.cache.Load().lookupPositive(reqPath)
	require.NotNil(t, e, "the mismatch must refresh the entry")
	require.EqualValues(t, len("second body, longer"), e.size)
}

// TestFreshFileIsNotCached covers the settle window: a file written moments ago may still change inside one mtime tick, so it is served but not cached.
func TestFreshFileIsNotCached(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeFile(t, dir, "fresh.txt", "just written")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})
	c := countingRoot(p)

	require.Equal(t, http.StatusOK, requestPath(t, h, reqPath))
	require.Nil(t, p.cache.Load().lookupPositive(reqPath), "a file inside the settle window is not cached")

	reads := c.reads.Load()
	require.Positive(t, reads, "the strong validator reads the body")

	require.Equal(t, http.StatusOK, requestPath(t, h, reqPath))
	require.Greater(t, c.reads.Load(), reads, "an uncached file is read again")
}

// TestIsMissingOnlyMatchesAbsentFiles pins the error classification: only a genuine absence may be remembered as a miss.
func TestIsMissingOnlyMatchesAbsentFiles(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"wrapped_not_exist", fmt.Errorf("open failed: %w", fs.ErrNotExist), true},
		{"path_error", &fs.PathError{Op: "open", Path: "/x.txt", Err: fs.ErrNotExist}, true},
		{"permission", &fs.PathError{Op: "open", Path: "/x.txt", Err: fs.ErrPermission}, false},
		{"opaque", errors.New("too many open files"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isMissing(tt.err))
		})
	}
}

// TestTransientOpenErrorIsNotCached is the request-level half of the same rule: a descriptor or permission failure must not hide an existing file.
func TestTransientOpenErrorIsNotCached(t *testing.T) {
	h, p, fellThrough := servePluginCfg(t, &Config{Dir: t.TempDir()})
	p.root = errFS{err: &fs.PathError{Op: "open", Path: "/x.txt", Err: fs.ErrPermission}}

	require.Equal(t, http.StatusTeapot, requestPath(t, h, "/x.txt"))
	require.True(t, fellThrough.Load())
	require.False(t, p.cache.Load().lookupNegative("/x.txt"), "a transient error must not be cached")
}

// TestCacheKeyIsCanonical covers cardinality: paths that name the same file share one entry, so the map does not grow for each spelling.
func TestCacheKeyIsCanonical(t *testing.T) {
	dir := t.TempDir()
	writeAged(t, dir, "hello.txt", "hello")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	require.Equal(t, http.StatusOK, requestPath(t, h, "/hello.txt"))
	require.Equal(t, http.StatusOK, requestPath(t, h, "//hello.txt"))

	require.EqualValues(t, 1, p.cache.Load().posCount.Load())
	require.EqualValues(t, 1, countEntries(&p.cache.Load().positive))
}

// TestConditionalAndRangeOnWarmEntry covers the cached validator in use: it is stable, answers a conditional request without a file read, and does not disturb range handling.
func TestConditionalAndRangeOnWarmEntry(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeAged(t, dir, "a.txt", "0123456789abcdef")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})
	c := countingRoot(p)

	tag := serveRequest(t, h, request(t, http.MethodGet, reqPath)).etag()
	require.NotEmpty(t, tag)
	require.NotNil(t, p.cache.Load().lookupPositive(reqPath), "the file must be cached")

	require.Equal(t, tag, serveRequest(t, h, request(t, http.MethodGet, reqPath)).etag(),
		"a warm entry serves the same validator")

	reads := c.reads.Load()

	conditional := request(t, http.MethodGet, reqPath)
	conditional.Header.Set("If-None-Match", tag)
	resp := serveRequest(t, h, conditional)

	require.Equal(t, http.StatusNotModified, resp.status)
	require.Empty(t, resp.body)
	require.Equal(t, reads, c.reads.Load(), "a 304 must not read the file")

	ranged := request(t, http.MethodGet, reqPath)
	ranged.Header.Set("Range", "bytes=4-7")
	resp = serveRequest(t, h, ranged)

	require.Equal(t, http.StatusPartialContent, resp.status)
	require.Equal(t, "4567", resp.body)
}

// TestWarmEntryServesCachedValidator proves the hit path reuses the stored metadata: a same-size, same-mtime rewrite looks identical, so the cached etag goes out.
func TestWarmEntryServesCachedValidator(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "a.txt")
	reqPath := writeAged(t, dir, "a.txt", "first")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	tag := serveRequest(t, h, request(t, http.MethodGet, reqPath)).etag()
	require.NotEmpty(t, tag)

	e := p.cache.Load().lookupPositive(reqPath)
	require.NotNil(t, e)

	// same size, same mtime: nothing the fstat check can see changed
	mtime := time.Unix(e.mtimeSec, int64(e.mtimeNsec))
	require.NoError(t, os.WriteFile(name, []byte("secnd"), 0o600))
	require.NoError(t, os.Chtimes(name, mtime, mtime))

	resp := serveRequest(t, h, request(t, http.MethodGet, reqPath))

	require.Equal(t, "secnd", resp.body, "the body always comes from the fd")
	require.Equal(t, tag, resp.etag(), "the cached validator is reused")
}

// TestDerivedContentType covers the type an unknown extension gets: static sniffs it from the bytes in hand, and a configured header still wins.
func TestDerivedContentType(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeFile(t, dir, "blob.zzz", string([]byte{0x00, 0x01, 0x02, 0xff, 0xfe}))

	require.Empty(t, mime.TypeByExtension(".zzz"), "the test needs an extension the system does not know")

	t.Run("sniffed_from_body", func(t *testing.T) {
		h, _, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

		resp := serveRequest(t, h, request(t, http.MethodGet, reqPath))

		require.Equal(t, http.StatusOK, resp.status)
		require.Equal(t, "application/octet-stream", resp.header.Get("Content-Type"))
	})

	t.Run("configured_type_wins", func(t *testing.T) {
		h, _, _ := servePluginCfg(t, &Config{
			Dir:           dir,
			CalculateEtag: true,
			Response:      map[string]string{"Content-Type": "application/x-custom"},
		})

		resp := serveRequest(t, h, request(t, http.MethodGet, reqPath))

		require.Equal(t, "application/x-custom", resp.header.Get("Content-Type"))
	})
}

// TestReset covers the resetter hook: a flushed cache forgets a miss recorded before the file existed.
func TestReset(t *testing.T) {
	t.Run("flushes_a_negative_entry", func(t *testing.T) {
		dir := t.TempDir()
		h, p, _ := servePluginCfg(t, &Config{Dir: dir, CacheMissTTL: new(time.Hour)})

		require.Equal(t, http.StatusTeapot, requestPath(t, h, "/later.txt"))
		require.True(t, p.cache.Load().lookupNegative("/later.txt"))

		writeFile(t, dir, "later.txt", "here now")
		require.NoError(t, p.Reset())

		status, body := responseBody(t, h, "/later.txt")

		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "here now", body)
	})

	t.Run("no_op_without_init", func(t *testing.T) {
		require.NotPanics(t, func() {
			require.NoError(t, (&Plugin{}).Reset())
		})
	})

	t.Run("no_op_with_caching_off", func(t *testing.T) {
		_, p, _ := servePluginCfg(t, &Config{
			Dir:          t.TempDir(),
			CacheTTL:     new(time.Duration(0)),
			CacheMissTTL: new(time.Duration(0)),
		})

		require.NoError(t, p.Reset())
		require.Nil(t, p.cache.Load())
	})
}

// TestConcurrentRequestsWithReset is the race guard: hits, misses and cache flushes run at once with ttls short enough to expire mid-run.
func TestConcurrentRequestsWithReset(t *testing.T) {
	dir := t.TempDir()
	writeAged(t, dir, "hot.txt", strings.Repeat("x", 4096))

	h, p, _ := servePluginCfg(t, &Config{
		Dir:           dir,
		CalculateEtag: true,
		CacheTTL:      new(5 * time.Millisecond),
		CacheMissTTL:  new(5 * time.Millisecond),
	})

	ctx := t.Context()

	var unexpected atomic.Int64
	hit := func(path string, want int) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil))

		if rec.Code != want {
			unexpected.Add(1)
		}
	}

	stop := make(chan struct{})

	var resetter sync.WaitGroup
	resetter.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				if err := p.Reset(); err != nil {
					unexpected.Add(1)
				}

				time.Sleep(time.Millisecond)
			}
		}
	})

	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 200 {
				hit("/hot.txt", http.StatusOK)
				hit("/nope.txt", http.StatusTeapot)
			}
		})
	}

	workers.Wait()
	close(stop)
	resetter.Wait()

	require.Zero(t, unexpected.Load())
}

// fakeInfo is canned stat metadata.
type fakeInfo struct {
	name string
	size int64
	mode fs.FileMode
	mod  time.Time
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return i.mod }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }

// fakeFile fails on demand, so the error branches run without an exotic filesystem.
type fakeFile struct {
	*strings.Reader
	info     fakeInfo
	statErr  error
	readErr  error
	closeErr error
}

func (f *fakeFile) Close() error                       { return f.closeErr }
func (f *fakeFile) Readdir(int) ([]fs.FileInfo, error) { return nil, errors.New("not a directory") }

func (f *fakeFile) Stat() (fs.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}

	return f.info, nil
}

func (f *fakeFile) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}

	return f.Reader.Read(p)
}

// fakeFS hands out one canned file for each open.
type fakeFS struct{ open func() *fakeFile }

func (f fakeFS) Open(string) (http.File, error) { return f.open(), nil }

// settledInfo is metadata old enough for the middleware to cache.
func settledInfo(size int64) fakeInfo {
	return fakeInfo{name: "a.txt", size: size, mode: 0o644, mod: time.Now().Add(-time.Hour)}
}

func fakeRoot(p *Plugin, build func() *fakeFile) {
	p.root = fakeFS{open: build}
}

// TestFilesystemFaultsFallThrough covers the error branches around an open file: none may answer the request, they all belong to the worker.
func TestFilesystemFaultsFallThrough(t *testing.T) {
	tests := []struct {
		name  string
		build func() *fakeFile
	}{
		{"stat_error", func() *fakeFile {
			return &fakeFile{Reader: strings.NewReader("body"), statErr: errors.New("stat failed")}
		}},
		{"read_error", func() *fakeFile {
			return &fakeFile{
				Reader:  strings.NewReader("body"),
				info:    settledInfo(4),
				readErr: errors.New("input/output error"),
			}
		}},
		{"irregular_file", func() *fakeFile {
			info := settledInfo(0)
			info.mode = fs.ModeNamedPipe

			return &fakeFile{Reader: strings.NewReader(""), info: info}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, p, fellThrough := servePluginCfg(t, &Config{Dir: t.TempDir(), CalculateEtag: true})
			fakeRoot(p, tt.build)

			require.Equal(t, http.StatusTeapot, requestPath(t, h, "/a.txt"))
			require.True(t, fellThrough.Load(), "a faulty file must reach the worker")
			require.Nil(t, p.cache.Load().lookupPositive("/a.txt"), "a faulty file must not be cached")
		})
	}
}

// TestVerifiedHitSurvivesFaults covers the same faults through a warm entry: a stale cached validator must not leak into the response.
func TestVerifiedHitSurvivesFaults(t *testing.T) {
	warm := func(t *testing.T) (http.Handler, *Plugin, *atomic.Bool) {
		t.Helper()

		dir := t.TempDir()
		writeAged(t, dir, "a.txt", "body")

		h, p, fellThrough := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})
		require.Equal(t, http.StatusOK, requestPath(t, h, "/a.txt"))
		require.NotNil(t, p.cache.Load().lookupPositive("/a.txt"))
		fellThrough.Store(false)

		return h, p, fellThrough
	}

	t.Run("stat_error", func(t *testing.T) {
		h, p, fellThrough := warm(t)
		fakeRoot(p, func() *fakeFile {
			return &fakeFile{Reader: strings.NewReader("body"), statErr: errors.New("stat failed")}
		})

		require.Equal(t, http.StatusTeapot, requestPath(t, h, "/a.txt"))
		require.True(t, fellThrough.Load())
	})

	t.Run("became_a_directory", func(t *testing.T) {
		h, p, fellThrough := warm(t)
		fakeRoot(p, func() *fakeFile {
			info := settledInfo(0)
			info.mode = fs.ModeDir | 0o755

			return &fakeFile{Reader: strings.NewReader(""), info: info}
		})

		require.Equal(t, http.StatusTeapot, requestPath(t, h, "/a.txt"))
		require.True(t, fellThrough.Load())
		require.Nil(t, p.cache.Load().lookupPositive("/a.txt"), "the stale entry must be dropped")
		require.True(t, p.cache.Load().lookupNegative("/a.txt"))
	})
}

// TestShrunkFileServesActualBytesWithStrongEtag covers the race where the file loses bytes between the stat and the read: a read to EOF serves the actual bytes with a matching strong validator.
func TestShrunkFileServesActualBytesWithStrongEtag(t *testing.T) {
	h, p, _ := servePluginCfg(t, &Config{Dir: t.TempDir(), CalculateEtag: true})
	fakeRoot(p, func() *fakeFile {
		// stat says 32 bytes, the file only has 5 left
		return &fakeFile{Reader: strings.NewReader("short"), info: settledInfo(32)}
	})

	resp := serveRequest(t, h, request(t, http.MethodGet, "/a.txt"))

	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, "short", resp.body)
	require.NotEmpty(t, resp.etag(), "the strong validator describes the bytes actually served")
	require.Equal(t, "5", resp.header.Get("Content-Length"), "the response is self-consistent")
}

// TestCloseErrorDoesNotBreakTheResponse covers the close branch: a failing close is logged and never changes what the client got.
func TestCloseErrorDoesNotBreakTheResponse(t *testing.T) {
	h, p, _ := servePluginCfg(t, &Config{Dir: t.TempDir()})
	fakeRoot(p, func() *fakeFile {
		return &fakeFile{
			Reader:   strings.NewReader("body"),
			info:     settledInfo(4),
			closeErr: errors.New("close failed"),
		}
	})

	status, body := responseBody(t, h, "/a.txt")

	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "body", body)
}

// TestControlCharactersFallThrough covers the dropped CR/LF scrub: a control character is no longer stripped, so the path fails to resolve and falls through.
func TestControlCharactersFallThrough(t *testing.T) {
	dir := t.TempDir()
	writeAged(t, dir, "hello.txt", "hello world")

	h, _, fellThrough := servePluginCfg(t, &Config{Dir: dir})

	// a real server rejects control characters in the request line, so this one is built directly
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/hel\r\nlo.txt"},
		Header: make(http.Header),
	}

	resp := serveRequest(t, h, req.WithContext(t.Context()))

	require.Equal(t, http.StatusTeapot, resp.status)
	require.True(t, fellThrough.Load(), "a path with control characters does not resolve")
	require.NotContains(t, resp.body, "hello world")
}

// TestRequestHeadersReachTheHandler covers the request-header injection: the values land on the request that the precondition checks read.
func TestRequestHeadersReachTheHandler(t *testing.T) {
	dir := t.TempDir()
	reqPath := writeAged(t, dir, "a.txt", "body")

	h, _, _ := servePluginCfg(t, &Config{Dir: dir, Request: map[string]string{"X-Static": "yes"}})

	req := request(t, http.MethodGet, reqPath)

	require.Equal(t, http.StatusOK, serveRequest(t, h, req).status)
	require.Equal(t, "yes", req.Header.Get("X-Static"))
}

// TestForbidBypassClosed covers the forbid bypass: "/secret.php/." cleans to "/secret.php" before the extension gate, so static catches the forbidden extension.
func TestForbidBypassClosed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "secret.php", "<?php $key = 'leak'; ?>")

	h, _, fellThrough := servePluginCfg(t, &Config{Dir: dir, Forbid: []string{".php"}})

	resp := serveRequest(t, h, request(t, http.MethodGet, "/secret.php/."))

	require.Equal(t, http.StatusTeapot, resp.status, "the forbidden file must fall through")
	require.True(t, fellThrough.Load())
	require.NotContains(t, resp.body, "leak", "the source must not be served")
}

// TestContentTypePoisoningClosed covers poisoning through a dirty path: the dirty spelling and the canonical URL share one cache key, so the canonical URL keeps the extension content type.
func TestContentTypePoisoningClosed(t *testing.T) {
	dir := t.TempDir()
	writeAged(t, dir, "upload.txt", "<html><body>hi</body></html>")

	h, _, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	require.Equal(t, http.StatusOK, requestPath(t, h, "/upload.txt/."))

	resp := serveRequest(t, h, request(t, http.MethodGet, "/upload.txt"))

	require.Equal(t, http.StatusOK, resp.status)
	ctype := resp.header.Get("Content-Type")
	require.True(t, strings.HasPrefix(ctype, "text/plain"),
		"the canonical URL keeps the .txt type, got %q", ctype)
	require.False(t, strings.HasPrefix(ctype, "text/html"), "the body-sniffed type must not leak")
}

// TestPrefixGateCanonicalizesLeadingSlashes covers the prefix gate on the canonical path: a doubled leading slash cleans to the real path before the prefix check, so the file is still served.
func TestPrefixGateCanonicalizesLeadingSlashes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("var a=1"), 0o600))

	h, _, fellThrough := servePluginCfg(t, &Config{Dir: dir, Prefixes: []string{"/assets/"}})

	status, body := responseBody(t, h, "//assets/app.js")

	require.Equal(t, http.StatusOK, status, "the canonical path is inside the prefix and is served")
	require.Equal(t, "var a=1", body)
	require.False(t, fellThrough.Load())
}

// TestSameSizeDifferentMtimeRefills isolates the mtime half of the fstat check: a warm entry whose file gets same-length content at a different settled mtime is re-read, so the strong etag follows the new bytes.
func TestSameSizeDifferentMtimeRefills(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "a.txt")
	reqPath := writeAged(t, dir, "a.txt", "first")

	h, p, _ := servePluginCfg(t, &Config{Dir: dir, CalculateEtag: true})

	first := serveRequest(t, h, request(t, http.MethodGet, reqPath)).etag()
	require.NotEmpty(t, first)

	e := p.cache.Load().lookupPositive(reqPath)
	require.NotNil(t, e)

	// same length, different content, a distinct mtime still outside the settle window: only the mtime tells the versions apart
	require.NoError(t, os.WriteFile(name, []byte("secnd"), 0o600))
	newMod := time.Unix(e.mtimeSec, int64(e.mtimeNsec)).Add(-time.Minute)
	require.NoError(t, os.Chtimes(name, newMod, newMod))

	resp := serveRequest(t, h, request(t, http.MethodGet, reqPath))

	require.Equal(t, "secnd", resp.body)
	require.NotEqual(t, first, resp.etag(), "the mtime mismatch must refill and re-hash")
}
