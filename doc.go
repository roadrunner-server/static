// Package static provides an HTTP middleware that serves static files from a
// configured directory. It supports extension-based allow and forbid lists,
// ETag generation, and custom request and response headers. The middleware
// forwards a request that matches no static file to the next handler.
package static
