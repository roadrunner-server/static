package static

import (
	"os"

	"github.com/roadrunner-server/errors"
)

// Config describes file location and controls access to them.
type Config struct {
	// Dir contains name of directory to control access to.
	// Default - "."
	Dir string `mapstructure:"dir"`

	// CalculateEtag can be true/false and used to calculate etag for the static
	CalculateEtag bool `mapstructure:"calculate_etag"`

	// Weak etag `W/`
	Weak bool `mapstructure:"weak"`

	// forbid specifies a list of file extensions which are forbidden for access.
	// example: .php, .exe, .bat, .htaccess etc.
	Forbid []string `mapstructure:"forbid"`

	// Allow specifies a list of file extensions which are allowed for access.
	// example: .php, .exe, .bat, .htaccess etc.
	Allow []string `mapstructure:"allow"`

	// Request headers to add to every static.
	Request map[string]string `mapstructure:"request"`

	// Response headers to add to every static.
	Response map[string]string `mapstructure:"response"`

	// GzipEnabled determines if gzip compression is enabled for serving static files.
	GzipEnabled bool `mapstructure:"gzip_enabled"`

	// GzipMaxFileSize specifies the maximum size (in MB) of a file eligible for gzip compression.
	GzipMaxFileSize int `mapstructure:"max_size_compressed_file"`
}

// Valid returns nil if config is valid.
func (c *Config) Valid() error {
	const op = errors.Op("static_plugin_valid")
	st, err := os.Stat(c.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.E(op, errors.Errorf("root directory '%s' does not exists", c.Dir))
		}

		return err
	}

	if !st.IsDir() {
		return errors.E(op, errors.Errorf("invalid root directory '%s'", c.Dir))
	}

	return nil
}

func (c *Config) InitDefaults() {
	if c.GzipMaxFileSize == 0 {
		c.GzipMaxFileSize = 10 // In MB
	}
}
