package static

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValid(t *testing.T) {
	t.Run("existing_directory", func(t *testing.T) {
		c := &Config{Dir: t.TempDir()}
		require.NoError(t, c.Valid())
	})

	t.Run("missing_directory", func(t *testing.T) {
		c := &Config{Dir: filepath.Join(t.TempDir(), "no-such-dir")}

		err := c.Valid()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist",
			"a missing root directory must report that it does not exist")
	})

	t.Run("path_points_to_a_file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file.txt")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

		c := &Config{Dir: file}

		err := c.Valid()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid root directory",
			"a regular file used as root must be rejected as an invalid directory")
	})
}
