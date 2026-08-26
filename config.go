package static

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	rrerrors "github.com/roadrunner-server/errors"
)

const (
	defaultCacheTTL        = 10 * time.Second
	defaultCacheMissTTL    = 10 * time.Second
	defaultCacheMaxEntries = 16384
)

// Config describes the file location and controls access to the files.
type Config struct {
	// Dir is the name of the directory to control access to.
	// The default is ".".
	Dir string `mapstructure:"dir"`

	// CalculateEtag turns on etag calculation for static files.
	CalculateEtag bool `mapstructure:"calculate_etag"`

	// Weak turns the etag into a weak validator (`W/`).
	Weak bool `mapstructure:"weak"`

	// Forbid lists the file extensions the plugin does not serve.
	// For example: .php, .exe, .bat, .htaccess.
	Forbid []string `mapstructure:"forbid"`

	// Allow lists the file extensions the plugin serves.
	// For example: .php, .exe, .bat, .htaccess.
	Allow []string `mapstructure:"allow"`

	// Request lists the headers to add to each static request.
	Request map[string]string `mapstructure:"request"`

	// Response lists the headers to add to each static response.
	Response map[string]string `mapstructure:"response"`

	// Prefixes, when set, limit static serving to request paths that start with
	// one of these prefixes. The match uses raw strings.HasPrefix semantics.
	Prefixes []string `mapstructure:"prefixes"`

	// CacheTTL is the positive metadata cache TTL. A nil value means the 10s
	// default. An explicit 0 turns the positive cache off.
	CacheTTL *time.Duration `mapstructure:"cache_ttl"`

	// CacheMissTTL is the miss cache TTL. A nil value means the 10s default. An
	// explicit 0 turns the miss cache off.
	CacheMissTTL *time.Duration `mapstructure:"cache_miss_ttl"`

	// CacheMaxEntries caps each cache map. A 0 value means the 16384 default.
	CacheMaxEntries int `mapstructure:"cache_max_entries"`

	// Valid resolves these fields.
	cacheTTL        time.Duration // 10s default, 0 = positive cache off
	cacheMissTTL    time.Duration // 10s default, 0 = miss cache off
	cacheMaxEntries int64         // 16384 default
}

// Valid returns nil when the config is valid.
func (c *Config) Valid() error {
	const op = rrerrors.Op("static_plugin_valid")
	st, err := os.Stat(c.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return rrerrors.E(op, rrerrors.Errorf("root directory '%s' does not exists", c.Dir))
		}

		return rrerrors.E(op, err)
	}

	if !st.IsDir() {
		return rrerrors.E(op, rrerrors.Errorf("invalid root directory '%s'", c.Dir))
	}

	for _, p := range c.Prefixes {
		if !strings.HasPrefix(p, "/") {
			return rrerrors.E(op, rrerrors.Errorf("prefix should start with '/', got: '%s'", p))
		}
	}

	return c.resolveCache()
}

// resolveCache checks the cache settings and fills the resolved fields. A nil
// TTL means the default. An explicit 0 turns that cache off.
func (c *Config) resolveCache() error {
	const op = rrerrors.Op("static_plugin_valid")

	var err error
	if c.cacheTTL, err = resolveTTL(c.CacheTTL, defaultCacheTTL, "cache_ttl"); err != nil {
		return rrerrors.E(op, err)
	}

	if c.cacheMissTTL, err = resolveTTL(c.CacheMissTTL, defaultCacheMissTTL, "cache_miss_ttl"); err != nil {
		return rrerrors.E(op, err)
	}

	if c.CacheMaxEntries < 0 {
		return rrerrors.E(op, rrerrors.Errorf("cache_max_entries must not be negative, got: '%d'", c.CacheMaxEntries))
	}

	c.cacheMaxEntries = cmp.Or(int64(c.CacheMaxEntries), defaultCacheMaxEntries)

	return nil
}

func resolveTTL(v *time.Duration, def time.Duration, key string) (time.Duration, error) {
	if v == nil {
		return def, nil
	}

	if *v < 0 {
		return 0, rrerrors.Errorf("%s must not be negative, got: '%s'", key, *v)
	}

	return *v, nil
}
