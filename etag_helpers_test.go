package static

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStrongEtagGoldenValue pins the exact output: 17 bytes of body and the Castagnoli crc32 of "roadrunner static".
func TestStrongEtagGoldenValue(t *testing.T) {
	require.Equal(t, `"17-1546106790"`, strongEtag([]byte("roadrunner static")))
	require.Equal(t, `"1-3251651376"`, strongEtag([]byte("a")))
}

func TestStrongEtagEmptyBody(t *testing.T) {
	require.Empty(t, strongEtag(nil))
	require.Empty(t, strongEtag([]byte{}))
}

func TestStrongEtagFollowsContent(t *testing.T) {
	require.NotEqual(t, strongEtag([]byte("one")), strongEtag([]byte("two")))
}

func TestWeakEtagFormat(t *testing.T) {
	require.Equal(t, `W/"1024-1700000000.250"`, weakEtag(1024, 1700000000, 250))
	require.Equal(t, `W/"0-0.0"`, weakEtag(0, 0, 0), "empty files still get a weak validator")
}

func TestWeakEtagFollowsMetadata(t *testing.T) {
	base := weakEtag(1024, 1700000000, 250)

	require.NotEqual(t, base, weakEtag(1025, 1700000000, 250), "size must change the validator")
	require.NotEqual(t, base, weakEtag(1024, 1700000001, 250), "mtime seconds must change the validator")
	require.NotEqual(t, base, weakEtag(1024, 1700000000, 251), "mtime nanoseconds must change the validator")
}
