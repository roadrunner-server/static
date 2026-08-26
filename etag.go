package static

import (
	"hash/crc32"
	"strconv"
)

const etag string = "Etag"

// strongEtag returns the content etag in the "<size>-<crc>" form. An empty
// body gets no strong validator.
func strongEtag(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	// crc32 caches the Castagnoli table and picks the hardware implementation.
	sum := crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli))

	buf := make([]byte, 0, 32)
	buf = append(buf, '"')
	buf = strconv.AppendInt(buf, int64(len(body)), 10)
	buf = append(buf, '-')
	buf = strconv.AppendUint(buf, uint64(sum), 10)
	buf = append(buf, '"')

	return bytesToStr(buf)
}

// weakEtag derives a validator from file metadata.
func weakEtag(size int64, mtimeSec int64, mtimeNsec int32) string {
	buf := make([]byte, 0, 48)
	buf = append(buf, 'W', '/', '"')
	buf = strconv.AppendInt(buf, size, 10)
	buf = append(buf, '-')
	buf = strconv.AppendInt(buf, mtimeSec, 10)
	buf = append(buf, '.')
	buf = strconv.AppendInt(buf, int64(mtimeNsec), 10)
	buf = append(buf, '"')

	return bytesToStr(buf)
}
