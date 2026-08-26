package static

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	rrcontext "github.com/roadrunner-server/context"
	rrerrors "github.com/roadrunner-server/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	jprop "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.opentelemetry.io/otel/trace"
)

// PluginName is the default service name.
const (
	PluginName     = "static"
	RootPluginName = "http"
	cfgKey         = RootPluginName + "." + PluginName
)

const (
	contentType = "Content-Type"
	etagMaxSize = 32 << 20
	mtimeSettle = 2 * time.Second
)

type Configurer interface {
	UnmarshalKey(name string, out any) error
	Has(name string) bool
}

type Logger interface {
	NamedLogger(name string) *slog.Logger
}

// Plugin serves static files.
type Plugin struct {
	// the server configuration (location, forbidden files)
	cfg *Config
	log *slog.Logger

	// root is the http directory to serve from
	root http.FileSystem
	// file extensions the plugin allows
	allowedExtensions   map[string]struct{}
	forbiddenExtensions map[string]struct{}
	prop                propagation.TextMapPropagator
	cache               atomic.Pointer[cacheState]
	positiveCache       bool
}

// Init sets up the plugin from its config. It returns a Disabled error when the
// config is absent, and another error when the config is invalid. The plugin
// must not run without a valid config.
func (s *Plugin) Init(cfg Configurer, log Logger) error {
	const op = rrerrors.Op("static_plugin_init")
	if !cfg.Has(RootPluginName) {
		return rrerrors.E(op, rrerrors.Disabled)
	}

	// http.static
	if !cfg.Has(cfgKey) {
		return rrerrors.E(op, rrerrors.Disabled)
	}

	err := cfg.UnmarshalKey(cfgKey, &s.cfg)
	if err != nil {
		return rrerrors.E(op, rrerrors.Disabled, err)
	}

	err = s.cfg.Valid()
	if err != nil {
		return rrerrors.E(op, err)
	}

	if s.cfg.cacheTTL > 0 || s.cfg.cacheMissTTL > 0 {
		s.storeFreshCache()
	}

	s.positiveCache = s.cfg.CalculateEtag && s.cfg.cacheTTL > 0

	// create two maps for the allowed and forbidden file extensions
	s.allowedExtensions = make(map[string]struct{}, len(s.cfg.Allow))
	s.forbiddenExtensions = make(map[string]struct{}, len(s.cfg.Forbid))

	s.log = log.NamedLogger(PluginName)
	s.root = http.Dir(s.cfg.Dir)

	// fill the forbidden map
	for _, ext := range s.cfg.Forbid {
		// skip empty lines
		if ext == "" {
			continue
		}
		s.forbiddenExtensions[ext] = struct{}{}
	}

	// fill the allowed map
	for _, ext := range s.cfg.Allow {
		// skip empty lines
		if ext == "" {
			continue
		}
		s.allowedExtensions[ext] = struct{}{}
	}

	// forbidden wins over allowed
	// drop any extension that appears in both maps
	for k := range s.forbiddenExtensions {
		delete(s.allowedExtensions, k)
	}

	s.prop = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, jprop.Jaeger{})

	return nil
}

func (s *Plugin) Name() string {
	return PluginName
}

// Reset clears the metadata cache. The resetter plugin calls it.
func (s *Plugin) Reset() error {
	if s.cfg == nil || s.cache.Load() == nil {
		return nil
	}

	s.storeFreshCache()

	return nil
}

func (s *Plugin) storeFreshCache() {
	s.cache.Store(newCacheState(s.cfg.cacheTTL, s.cfg.cacheMissTTL, s.cfg.cacheMaxEntries))
}

// serveState is the per-request state the serving helpers share.
type serveState struct {
	w    http.ResponseWriter
	r    *http.Request
	next http.Handler
	span trace.Span
	// cache is nil when the cache is off.
	cache *cacheState
	// fp is the canonical request path (path.Clean of the URL path).
	fp string
	// ext is the lowercased file extension.
	ext string
}

func (st *serveState) pass() {
	endSpan(st.span)
	st.next.ServeHTTP(st.w, st.r)
}

// Middleware returns a handler that serves static files. It forwards every
// other request to the next handler.
func (s *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var span trace.Span
		if val, ok := r.Context().Value(rrcontext.OtelTracerNameKey).(string); ok {
			tp := trace.SpanFromContext(r.Context()).TracerProvider()
			var ctx context.Context
			ctx, span = tp.Tracer(val, trace.WithSchemaURL(semconv.SchemaURL),
				trace.WithInstrumentationVersion(otelhttp.Version)).
				Start(r.Context(), PluginName, trace.WithSpanKind(trace.SpanKindInternal))

			s.prop.Inject(ctx, propagation.HeaderCarrier(r.Header))
			r = r.WithContext(ctx)
		}

		st := serveState{w: w, r: r, next: next, span: span}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			st.pass()
			return
		}

		// the canonical path drives every check, the file open, and the cache key
		st.fp = path.Clean("/" + r.URL.Path)
		if !s.prefixAllowed(st.fp) {
			st.pass()
			return
		}

		// skip files that have no extension
		st.ext = strings.ToLower(path.Ext(st.fp))
		if st.ext == "" {
			st.pass()
			return
		}

		// check the extension against the forbidden list
		if _, ok := s.forbiddenExtensions[st.ext]; ok {
			s.log.Debug("file extension is forbidden", "ext", st.ext)
			st.pass()
			return
		}

		// with a non-empty allow list, the extension must be in it
		// with an empty allow list, allow every extension except the forbidden ones
		if len(s.allowedExtensions) > 0 {
			// not found in allowed
			if _, ok := s.allowedExtensions[st.ext]; !ok {
				st.pass()
				return
			}
		}

		s.serve(&st)
	})
}

func (s *Plugin) prefixAllowed(p string) bool {
	if len(s.cfg.Prefixes) == 0 {
		return true
	}

	return slices.ContainsFunc(s.cfg.Prefixes, func(prefix string) bool {
		return strings.HasPrefix(p, prefix)
	})
}

func (s *Plugin) serve(st *serveState) {
	var e *cacheEntry

	st.cache = s.cache.Load()
	if st.cache != nil {
		if st.cache.lookupNegative(st.fp) {
			st.pass()
			return
		}

		if s.positiveCache {
			e = st.cache.lookupPositive(st.fp)
		}
	}

	s.openAndServe(st, e)
}

func (s *Plugin) openAndServe(st *serveState, e *cacheEntry) {
	f, err := s.root.Open(st.fp)
	if err != nil {
		if st.cache != nil && isMissing(err) {
			st.cache.dropPositive(st.fp)
			st.cache.storeNegative(st.fp)
		}

		s.log.Debug("file open error", "error", err)
		st.pass()
		return
	}

	finfo, err := f.Stat()
	if err != nil {
		s.closeFile(f)
		s.log.Debug("file stat error", "error", err)
		st.pass()
		return
	}

	if e != nil && sameFile(finfo, e) {
		// the fd goes to ServeContent so sendfile still applies
		defer s.closeFile(f)
		s.respond(st, finfo, f, e.etag, e.ctype)

		return
	}

	s.fillAndServe(st, f, finfo)
}

// sameFile reports whether the file on disk still matches the cached metadata.
func sameFile(finfo fs.FileInfo, e *cacheEntry) bool {
	if !finfo.Mode().IsRegular() || finfo.Size() != e.size {
		return false
	}

	sec, nsec := mtimeParts(finfo.ModTime())

	return sec == e.mtimeSec && nsec == e.mtimeNsec
}

func (s *Plugin) fillAndServe(st *serveState, f http.File, finfo fs.FileInfo) {
	if finfo.IsDir() {
		s.log.Warn("path to dir provided, not serving dir", "path", st.fp)

		if st.cache != nil {
			// the plugin never serves a directory, so a later file at the same
			// path shows up again after cacheMissTTL
			st.cache.dropPositive(st.fp)
			st.cache.storeNegative(st.fp)
		}

		s.closeFile(f)
		st.pass()
		return
	}

	if !finfo.Mode().IsRegular() {
		s.closeFile(f)
		st.pass()
		return
	}

	if s.cfg.CalculateEtag && !s.cfg.Weak && finfo.Size() <= etagMaxSize {
		s.serveBody(st, f, finfo)
		return
	}

	defer s.closeFile(f)

	var tag string
	if s.cfg.CalculateEtag && s.cfg.Weak {
		tag = weakEtagOf(finfo)
	}

	ctype := mime.TypeByExtension(st.ext)

	s.storeEntry(st, finfo, finfo.Size(), tag, ctype)
	s.respond(st, finfo, f, tag, ctype)
}

func (s *Plugin) serveBody(st *serveState, f http.File, finfo fs.FileInfo) {
	buf := bytes.NewBuffer(make([]byte, 0, finfo.Size()))
	_, err := buf.ReadFrom(f)
	s.closeFile(f)
	if err != nil {
		s.log.Debug("file read error", "error", err)
		st.pass()
		return
	}
	body := buf.Bytes()

	ctype := mime.TypeByExtension(st.ext)
	if ctype == "" {
		ctype = http.DetectContentType(body)
	}

	tag := strongEtag(body)
	s.storeEntry(st, finfo, int64(len(body)), tag, ctype)
	s.respond(st, finfo, bytes.NewReader(body), tag, ctype)
}

func (s *Plugin) storeEntry(st *serveState, finfo fs.FileInfo, size int64, tag, ctype string) {
	if st.cache == nil || !s.positiveCache {
		return
	}

	mtime := finfo.ModTime()
	if d := time.Since(mtime); d >= 0 && d < mtimeSettle {
		return
	}

	sec, nsec := mtimeParts(mtime)
	st.cache.storePositive(st.fp, &cacheEntry{
		size:      size,
		mtimeSec:  sec,
		mtimeNsec: nsec,
		etag:      tag,
		ctype:     ctype,
		filled:    time.Now(),
	})
}

func (s *Plugin) respond(st *serveState, finfo fs.FileInfo, content io.ReadSeeker, tag, ctype string) {
	h := st.w.Header()
	if tag != "" {
		h.Set(etag, tag)
	}

	for k, v := range s.cfg.Request {
		st.r.Header.Add(k, v)
	}

	if ctype != "" {
		h.Set(contentType, ctype)
	}

	for k, v := range s.cfg.Response {
		h.Set(k, v)
	}

	http.ServeContent(st.w, st.r, finfo.Name(), finfo.ModTime(), content)
	endSpan(st.span)
}

// weakEtagOf derives the metadata validator from a stat result.
func weakEtagOf(finfo fs.FileInfo) string {
	sec, nsec := mtimeParts(finfo.ModTime())

	return weakEtag(finfo.Size(), sec, nsec)
}

func mtimeParts(mtime time.Time) (int64, int32) {
	return mtime.Unix(), int32(mtime.Nanosecond()) //nolint:gosec // Nanosecond is below 1e9
}

func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func (s *Plugin) closeFile(f http.File) {
	if err := f.Close(); err != nil {
		s.log.Error("file close error", "error", err)
	}
}

// endSpan ends the span if it is not nil.
func endSpan(span trace.Span) {
	if span != nil {
		span.End()
	}
}

func bytesToStr(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	return unsafe.String(unsafe.SliceData(data), len(data))
}
