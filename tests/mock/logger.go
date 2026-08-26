package mocklogger

import (
	"log/slog"
)

// MockLogger implements the static.Logger interface for testing.
type MockLogger struct {
	log *slog.Logger
}

// NewMockLogger creates a MockLogger with an in-memory observer handler and returns it with an ObservedLogs.
func NewMockLogger(level slog.Level) (*MockLogger, *ObservedLogs) {
	handler, logs := NewObserverHandler(level)
	return &MockLogger{log: slog.New(handler)}, logs
}

// NamedLogger returns the underlying *slog.Logger to satisfy static.Logger.
func (m *MockLogger) NamedLogger(_ string) *slog.Logger {
	return m.log
}
