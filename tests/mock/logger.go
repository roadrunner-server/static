package mocklogger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// MockLogger implements the static.Logger interface for testing.
type MockLogger struct {
	log *zap.Logger
}

// NewMockLogger creates a MockLogger backed by an in-memory observed core.
// Returns the logger and an ObservedLogs for test assertions.
func NewMockLogger(enab zapcore.LevelEnabler) (*MockLogger, *ObservedLogs) {
	core, logs := New(enab)
	return &MockLogger{log: zap.New(core, zap.Development())}, logs
}

// NamedLogger returns the underlying zap.Logger, satisfying static.Logger.
func (m *MockLogger) NamedLogger(_ string) *zap.Logger {
	return m.log
}
