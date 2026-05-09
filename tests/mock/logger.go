package mocklogger

import (
	"log/slog"
)

// MockLogger implements the static.Logger interface for testing.
type MockLogger struct {
	log *slog.Logger
}

// NewMockLogger creates a MockLogger backed by an in-memory observer handler.
// Returns the logger and an ObservedLogs for test assertions.
func NewMockLogger(level slog.Level) (*MockLogger, *ObservedLogs) {
	handler, logs := NewObserverHandler(level)
	return &MockLogger{log: slog.New(handler)}, logs
}

// NamedLogger returns the underlying *slog.Logger, satisfying static.Logger.
func (m *MockLogger) NamedLogger(_ string) *slog.Logger {
	return m.log
}
