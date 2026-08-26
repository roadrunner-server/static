package static

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// discardWriter keeps the recorder allocations out of the benchmark numbers.
type discardWriter struct{ header http.Header }

func (d *discardWriter) Header() http.Header         { return d.header }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(int)             {}

// benchHandler builds the middleware over cfg with a trivial downstream handler.
func benchHandler(b *testing.B, cfg *Config) http.Handler {
	b.Helper()

	p := &Plugin{}
	require.NoError(b, p.Init(&stubConfigurer{sections: bothSections(), cfg: cfg}, discardLogger{}))

	return p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
}

// runBench warms the cache and then measures one request against target.
func runBench(b *testing.B, cfg *Config, target string) {
	b.Helper()

	h := benchHandler(b, cfg)
	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, target, nil)
	w := &discardWriter{header: make(http.Header)}

	h.ServeHTTP(w, req)

	b.ReportAllocs()

	for b.Loop() {
		h.ServeHTTP(w, req)
	}
}

// benchBoth runs the shipped defaults and the caching-off baseline, so a run carries its own before and after.
func benchBoth(b *testing.B, cfg func(dir string) *Config, target string) {
	b.Helper()

	b.Run("cached", func(b *testing.B) {
		runBench(b, cfg(b.TempDir()), target)
	})

	b.Run("uncached", func(b *testing.B) {
		c := cfg(b.TempDir())
		c.CacheTTL = new(time.Duration(0))
		c.CacheMissTTL = new(time.Duration(0))
		runBench(b, c, target)
	})
}

func BenchmarkMiddlewareMiss(b *testing.B) {
	benchBoth(b, func(dir string) *Config {
		return &Config{Dir: dir}
	}, "/api/data.json")
}

func BenchmarkMiddlewareHit(b *testing.B) {
	benchBoth(b, func(dir string) *Config {
		writeAged(b, dir, "asset.txt", strings.Repeat("a", 1<<10))

		return &Config{Dir: dir}
	}, "/asset.txt")
}

func BenchmarkMiddlewareHitStrongEtag(b *testing.B) {
	benchBoth(b, func(dir string) *Config {
		writeAged(b, dir, "asset.txt", strings.Repeat("a", 100<<10))

		return &Config{Dir: dir, CalculateEtag: true}
	}, "/asset.txt")
}
