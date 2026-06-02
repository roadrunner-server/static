package static

import (
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
)

const etag string = "Etag"

// weak Etag prefix, constant
var weakPrefix = []byte(`W/`) //nolint:gochecknoglobals

// CRC32 table, constant
var crc32q = crc32.MakeTable(0x48D90782) //nolint:gochecknoglobals

// SetEtag sets etag for the file
func SetEtag(weak bool, f http.File, name string, w http.ResponseWriter) {
	// preallocate
	calculatedEtag := make([]byte, 0, 64)

	// write weak
	if weak {
		calculatedEtag = append(calculatedEtag, weakPrefix...)
		calculatedEtag = append(calculatedEtag, '"')
		calculatedEtag = strconv.AppendUint(calculatedEtag, uint64(crc32.Checksum(strToBytes(name), crc32q)), 10)
		calculatedEtag = append(calculatedEtag, '"')

		w.Header().Set(etag, bytesToStr(calculatedEtag))
		return
	}

	// read the file content
	body, err := io.ReadAll(f)
	if err != nil {
		return
	}

	// skip for 0 body
	if len(body) == 0 {
		return
	}

	calculatedEtag = append(calculatedEtag, '"')
	calculatedEtag = strconv.AppendUint(calculatedEtag, uint64(len(body)), 10)
	calculatedEtag = append(calculatedEtag, '-')
	calculatedEtag = strconv.AppendUint(calculatedEtag, uint64(crc32.Checksum(body, crc32q)), 10)
	calculatedEtag = append(calculatedEtag, '"')

	w.Header().Set(etag, bytesToStr(calculatedEtag))
}
