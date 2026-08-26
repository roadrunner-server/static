package static

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/roadrunner-server/errors"
	"github.com/stretchr/testify/require"
)

// stubConfigurer hands Init a pre-built Config instead of decoding YAML.
type stubConfigurer struct {
	sections map[string]bool
	cfg      *Config
	err      error
}

func (s *stubConfigurer) Has(name string) bool { return s.sections[name] }

func (s *stubConfigurer) UnmarshalKey(_ string, out any) error {
	if s.err != nil {
		return s.err
	}

	p, ok := out.(**Config)
	if !ok {
		return errors.Str("unexpected target type")
	}
	*p = s.cfg
	return nil
}

type discardLogger struct{}

func (discardLogger) NamedLogger(string) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func bothSections() map[string]bool {
	return map[string]bool{RootPluginName: true, cfgKey: true}
}

func TestInitDisabledWithoutHTTPSection(t *testing.T) {
	err := (&Plugin{}).Init(&stubConfigurer{sections: map[string]bool{}}, discardLogger{})

	require.Error(t, err)
	require.True(t, errors.Is(errors.Disabled, err))
}

func TestInitDisabledWithoutStaticSection(t *testing.T) {
	err := (&Plugin{}).Init(&stubConfigurer{sections: map[string]bool{RootPluginName: true}}, discardLogger{})

	require.Error(t, err)
	require.True(t, errors.Is(errors.Disabled, err))
}

func TestInitDisabledWhenUnmarshalFails(t *testing.T) {
	c := &stubConfigurer{sections: bothSections(), err: errors.Str("broken config")}

	err := (&Plugin{}).Init(c, discardLogger{})

	require.Error(t, err)
	require.True(t, errors.Is(errors.Disabled, err))
}

func TestInitRejectsMissingRootDirectory(t *testing.T) {
	c := &stubConfigurer{sections: bothSections(), cfg: &Config{Dir: filepath.Join(t.TempDir(), "absent")}}

	err := (&Plugin{}).Init(c, discardLogger{})

	require.ErrorContains(t, err, "does not exists")
}

func TestInitRejectsFileAsRootDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	c := &stubConfigurer{sections: bothSections(), cfg: &Config{Dir: file}}

	err := (&Plugin{}).Init(c, discardLogger{})

	require.ErrorContains(t, err, "invalid root directory")
}

// TestInitDropsForbiddenFromAllowed covers the reconciliation step: an extension in both lists must not survive in the allowed set.
func TestInitDropsForbiddenFromAllowed(t *testing.T) {
	p := &Plugin{}
	c := &stubConfigurer{sections: bothSections(), cfg: &Config{
		Dir:    t.TempDir(),
		Allow:  []string{".txt", ".css", "", ".js"},
		Forbid: []string{".js", ""},
	}}

	require.NoError(t, p.Init(c, discardLogger{}))

	require.Contains(t, p.allowedExtensions, ".txt")
	require.Contains(t, p.allowedExtensions, ".css")
	require.NotContains(t, p.allowedExtensions, ".js")
	require.Contains(t, p.forbiddenExtensions, ".js")

	// static skips the empty entries in both lists; it does not store them
	require.NotContains(t, p.allowedExtensions, "")
	require.NotContains(t, p.forbiddenExtensions, "")
}

func TestName(t *testing.T) {
	require.Equal(t, PluginName, (&Plugin{}).Name())
}

func TestBytesToStrEmpty(t *testing.T) {
	require.Empty(t, bytesToStr(nil))
	require.Empty(t, bytesToStr([]byte{}))
	require.Equal(t, "abc", bytesToStr([]byte("abc")))
}
