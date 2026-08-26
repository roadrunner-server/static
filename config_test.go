package static

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestConfigCacheDefaults covers the nil-vs-zero distinction the pointer TTLs exist for: an absent key falls back to the default, an explicit 0 does not.
func TestConfigCacheDefaults(t *testing.T) {
	t.Run("unset_keys", func(t *testing.T) {
		c := &Config{Dir: t.TempDir()}
		require.NoError(t, c.Valid())

		assert.Equal(t, 10*time.Second, c.cacheTTL)
		assert.Equal(t, 10*time.Second, c.cacheMissTTL)
		assert.EqualValues(t, 16384, c.cacheMaxEntries)
	})

	t.Run("explicit_zero_ttls", func(t *testing.T) {
		c := &Config{Dir: t.TempDir(), CacheTTL: new(time.Duration(0)), CacheMissTTL: new(time.Duration(0))}
		require.NoError(t, c.Valid())

		assert.Zero(t, c.cacheTTL, "an explicit 0 disables the positive cache")
		assert.Zero(t, c.cacheMissTTL, "an explicit 0 disables the miss cache")
		assert.EqualValues(t, 16384, c.cacheMaxEntries, "the cap default is independent of the ttls")
	})

	t.Run("explicit_values", func(t *testing.T) {
		c := &Config{
			Dir:             t.TempDir(),
			CacheTTL:        new(2 * time.Second),
			CacheMissTTL:    new(3 * time.Second),
			CacheMaxEntries: 64,
			Prefixes:        []string{"/assets/", "/static"},
		}
		require.NoError(t, c.Valid())

		assert.Equal(t, 2*time.Second, c.cacheTTL)
		assert.Equal(t, 3*time.Second, c.cacheMissTTL)
		assert.EqualValues(t, 64, c.cacheMaxEntries)
	})
}

func TestConfigRejectsInvalidCacheSettings(t *testing.T) {
	t.Run("negative_cache_ttl", func(t *testing.T) {
		c := &Config{Dir: t.TempDir(), CacheTTL: new(-time.Second)}

		require.ErrorContains(t, c.Valid(), "cache_ttl")
	})

	t.Run("negative_cache_miss_ttl", func(t *testing.T) {
		c := &Config{Dir: t.TempDir(), CacheMissTTL: new(-time.Second)}

		require.ErrorContains(t, c.Valid(), "cache_miss_ttl")
	})

	t.Run("negative_max_entries", func(t *testing.T) {
		c := &Config{Dir: t.TempDir(), CacheMaxEntries: -1}

		require.ErrorContains(t, c.Valid(), "cache_max_entries")
	})

	t.Run("prefix_without_leading_slash", func(t *testing.T) {
		c := &Config{Dir: t.TempDir(), Prefixes: []string{"/assets", "static"}}

		err := c.Valid()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "static", "the offending prefix must be named")
	})
}
