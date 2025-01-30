package static

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"unsafe"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/roadrunner-server/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	jprop "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// PluginName contains default service name.
const (
	PluginName     = "static"
	RootPluginName = "http"
)

type Configurer interface {
	// UnmarshalKey takes a single key and unmarshal it into a Struct.
	UnmarshalKey(name string, out any) error
	// Has checks if a config section exists.
	Has(name string) bool
}

type Logger interface {
	NamedLogger(name string) *zap.Logger
}

// Plugin serves static files. Potentially convert into middleware?
type Plugin struct {
	// server configuration (location, forbidden files etc)
	cfg *Config
	log *zap.Logger

	// root is initiated http directory
	root http.Dir
	// file extensions which are allowed to be served
	allowedExtensions map[string]struct{}
	// file extensions which are forbidden to be served
	forbiddenExtensions map[string]struct{}
	// opentelemetry
	prop propagation.TextMapPropagator

	// gzipEnabled indicates if gzip compression is enabled for serving static files.
	gzipEnabled bool

	// gzipMaxFileSize specifies the maximum file size (in bytes) eligible for gzip compression when serving static files.
	gzipMaxFileSize int

	// cacheMutex is used to ensure thread-safety when accessing or modifying caching-related operations.
	cacheMutex sync.Mutex
}

// Init must return configure service and return true if the service hasStatus enabled. Must return error in case of
// misconfiguration. Services must not be used without proper configuration pushed first.
func (s *Plugin) Init(cfg Configurer, log Logger) error {
	const op = errors.Op("static_plugin_init")
	if !cfg.Has(RootPluginName) {
		return errors.E(op, errors.Disabled)
	}

	// http.static
	if !cfg.Has(fmt.Sprintf("%s.%s", RootPluginName, PluginName)) {
		return errors.E(op, errors.Disabled)
	}

	err := cfg.UnmarshalKey(fmt.Sprintf("%s.%s", RootPluginName, PluginName), &s.cfg)
	if err != nil {
		return errors.E(op, errors.Disabled, err)
	}

	s.cfg.InitDefaults()
	err = s.cfg.Valid()
	if err != nil {
		return errors.E(op, err)
	}

	// create 2 hashmaps with the allowed and forbidden file extensions
	s.allowedExtensions = make(map[string]struct{}, len(s.cfg.Allow))
	s.forbiddenExtensions = make(map[string]struct{}, len(s.cfg.Forbid))

	s.log = log.NamedLogger(PluginName)
	s.root = http.Dir(s.cfg.Dir)
	s.gzipEnabled = s.cfg.GzipEnabled
	s.gzipMaxFileSize = s.cfg.GzipMaxFileSize

	// init forbidden
	for i := 0; i < len(s.cfg.Forbid); i++ {
		// skip empty lines
		if s.cfg.Forbid[i] == "" {
			continue
		}
		s.forbiddenExtensions[s.cfg.Forbid[i]] = struct{}{}
	}

	// init allowed
	for i := 0; i < len(s.cfg.Allow); i++ {
		// skip empty lines
		if s.cfg.Allow[i] == "" {
			continue
		}
		s.allowedExtensions[s.cfg.Allow[i]] = struct{}{}
	}

	// check if any forbidden items presented in the allowed
	// if presented, delete such items from allowed
	for k := range s.forbiddenExtensions {
		delete(s.allowedExtensions, k)
	}

	s.prop = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, jprop.Jaeger{})

	// at this point we have distinct allowed and forbidden hashmaps, also with alwaysServed
	return nil
}

func (s *Plugin) Name() string {
	return PluginName
}

// Middleware must return true if a request/response pair is handled within the middleware.
func (s *Plugin) Middleware(next http.Handler) http.Handler { //nolint:gocognit,gocyclo
	// Define the http.HandlerFunc
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val, ok := r.Context().Value(rrcontext.OtelTracerNameKey).(string); ok {
			tp := trace.SpanFromContext(r.Context()).TracerProvider()
			ctx, span := tp.Tracer(val, trace.WithSchemaURL(semconv.SchemaURL),
				trace.WithInstrumentationVersion(otelhttp.Version())).
				Start(r.Context(), PluginName, trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()

			// inject
			s.prop.Inject(ctx, propagation.HeaderCarrier(r.Header))
			r = r.WithContext(ctx)
		}

		// do not allow paths like '../../resource'
		// only specified folder and resources in it
		// https://lgtm.com/rules/1510366186013/
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// first - create a proper file path
		fp := r.URL.Path
		fp = strings.ReplaceAll(fp, "\n", "")
		fp = strings.ReplaceAll(fp, "\r", "")
		ext := strings.ToLower(path.Ext(fp))

		// files w/o extensions are not allowed
		if ext == "" {
			next.ServeHTTP(w, r)
			return
		}

		// check that file extension in the forbidden list
		if _, ok := s.forbiddenExtensions[ext]; ok {
			ext = strings.ReplaceAll(ext, "\n", "")
			ext = strings.ReplaceAll(ext, "\r", "")
			s.log.Debug("file extension is forbidden", zap.String("ext", ext))
			next.ServeHTTP(w, r)
			return
		}

		// if we have some allowed extensions, we should check them
		// if not - all extensions allowed except forbidden
		if len(s.allowedExtensions) > 0 {
			// not found in allowed
			if _, ok := s.allowedExtensions[ext]; !ok {
				next.ServeHTTP(w, r)
				return
			}

			// file extension allowed
		}

		// ok, file is not in the forbidden list
		// Stat it and get file info
		f, err := s.root.Open(fp)
		if err != nil {
			// else no such file, show error in logs only in debug mode
			s.log.Debug("no such file or directory", zap.Error(err))
			// pass request to the worker
			next.ServeHTTP(w, r)
			return
		}

		// at high confidence here should not be an error
		// because we stat-ed the path previously and know, that that is file (not a dir), and it exists
		finfo, err := f.Stat()
		if err != nil {
			// else no such file, show error in logs only in debug mode
			s.log.Debug("no such file or directory", zap.Error(err))
			// pass request to the worker
			next.ServeHTTP(w, r)
			return
		}

		defer func() {
			err = f.Close()
			if err != nil {
				s.log.Error("file close error", zap.Error(err))
			}
		}()

		// if provided path to the dir, do not serve the dir, but pass the request to the worker
		if finfo.IsDir() {
			s.log.Debug("possible path to dir provided")
			// pass request to the worker
			next.ServeHTTP(w, r)
			return
		}

		// set etag
		if s.cfg.CalculateEtag {
			SetEtag(s.cfg.Weak, f, finfo.Name(), w)
		}

		if s.cfg.Request != nil {
			for k, v := range s.cfg.Request {
				r.Header.Add(k, v)
			}
		}

		if s.cfg.Response != nil {
			for k, v := range s.cfg.Response {
				w.Header().Set(k, v)
			}
		}

		if s.gzipEnabled && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			s.log.Debug("gzip compression requested")
			// Skip compression for already compressed formats
			contentType := http.DetectContentType(make([]byte, 512))
			if strings.Contains(contentType, "image/") ||
				strings.Contains(contentType, "video/") ||
				strings.Contains(contentType, "audio/") {
				s.log.Debug("skipping compression for already compressed content",
					zap.String("type", contentType))
				http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), f)
				return
			}

			cf, err := s.compressContent(fp, f)
			if err != nil {
				s.log.Error("failed to compress content", zap.Error(err))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			err = f.Close()
			if err != nil {
				s.log.Error("failed to close file", zap.Error(err))
			}
			f = cf
			// No new defer to close needed for cf. f is already closed, previous defer exist
			w.Header().Set("Content-Encoding", "gzip")
		}

		// we passed all checks - serve the file
		http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), f)
	})
}

func (s *Plugin) createCompressedFile(originalFile http.File, compressedPath string) error {
	// Prevent path traversal
	if !strings.HasPrefix(compressedPath, "/") {
		compressedPath = "/" + compressedPath
	}
	cleanPath := path.Clean(compressedPath)
	if !strings.HasPrefix(cleanPath, "/") {
		return fmt.Errorf("invalid path")
	}

	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	// We check again to avoid a race between threads.
	if _, err := os.Stat(compressedPath); err == nil {
		return nil
	}

	tempFile, err := os.CreateTemp(s.cfg.Dir, "gzip-*.tmp")
	if err != nil {
		return err
	}

	tempName := tempFile.Name()

	// Limit the size of compressed files
	maxSize := int64(s.gzipMaxFileSize * 1024 * 1024)
	limitedReader := io.LimitReader(originalFile, maxSize)
	gz := gzip.NewWriter(tempFile)

	defer func() {
		err = tempFile.Close()
		if err != nil {
			s.log.Error("failed to close file", zap.Error(err))
		}

		err = gz.Close()
		if err != nil {
			s.log.Error("failed to close file", zap.Error(err))
		}
	}()

	_, err = io.Copy(gz, limitedReader)
	if err != nil {
		return err
	}

	// Atomically rename the temp file to the final compressed file
	return os.Rename(tempName, s.cfg.Dir+cleanPath)
}

func (s *Plugin) compressContent(originalFilePath string, originalFile http.File) (http.File, error) {
	compressedFilePath := s.cfg.Dir + originalFilePath + ".gz"

	if _, err := os.Stat(compressedFilePath); os.IsNotExist(err) {
		s.log.Debug("Compressed file does not exist, creating it: ", zap.String("path", compressedFilePath))
		if err := s.createCompressedFile(originalFile, compressedFilePath); err != nil {
			s.log.Debug("Error creating compressed file: ", zap.Error(err))
			return nil, err
		}
	} else {
		s.log.Debug("GZ file already exists, skipping compression")
	}

	compressedFile, err := s.root.Open(compressedFilePath)
	if err != nil {
		s.log.Debug("Unable to open compressed file: ", zap.Error(err))
		return nil, err
	}

	return compressedFile, nil
}

func bytesToStr(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	return unsafe.String(unsafe.SliceData(data), len(data))
}

func strToBytes(data string) []byte {
	if data == "" {
		return nil
	}

	return unsafe.Slice(unsafe.StringData(data), len(data))
}
