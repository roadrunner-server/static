// Package static provides an HTTP middleware that serves static files from a
// configured directory. It supports extension-based allow/forbid lists, ETag
// generation, and custom request/response headers. Requests that do not match
// a static file are forwarded to the next handler in the chain.
package static
