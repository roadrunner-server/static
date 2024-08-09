package static

import (
	"hash/crc32"
	"io"
	"net/http"
)

const etag string = "Etag"

// weak Etag prefix, constant
var weakPrefix = []byte(`W/`) //nolint:gochecknoglobals

// CRC32 table, constant
var crc32q = crc32.MakeTable(0x48D90782) //nolint:gochecknoglobals

func calculateEtag(weak bool, f http.File, name string) []byte {
	// preallocate
	calculatedEtag := make([]byte, 0, 64)

	if weak {
		calculatedEtag = append(calculatedEtag, weakPrefix...)
		calculatedEtag = append(calculatedEtag, '"')
		calculatedEtag = appendUint(calculatedEtag, crc32.Checksum(strToBytes(name), crc32q))
		calculatedEtag = append(calculatedEtag, '"')
		return calculatedEtag
	}

	// read the file content
	body, err := io.ReadAll(f)
	if err != nil {
		return calculatedEtag
	}

	// skip for 0 body
	if len(body) == 0 {
		return calculatedEtag
	}

	calculatedEtag = append(calculatedEtag, '"')
	calculatedEtag = appendUint(calculatedEtag, uint32(len(body)))
	calculatedEtag = append(calculatedEtag, '-')
	calculatedEtag = appendUint(calculatedEtag, crc32.Checksum(body, crc32q))
	calculatedEtag = append(calculatedEtag, '"')

	return calculatedEtag
}

// SetEtag sets etag for the file
func SetEtag(w http.ResponseWriter, calculatedEtag []byte) {
	w.Header().Set(etag, bytesToStr(calculatedEtag))
}

// appendUint appends n to dst and returns the extended dst.
func appendUint(dst []byte, n uint32) []byte {
	var b [20]byte
	buf := b[:]
	i := len(buf)
	var q uint32
	for n >= 10 {
		i--
		q = n / 10
		buf[i] = '0' + byte(n-q*10)
		n = q
	}
	i--
	buf[i] = '0' + byte(n)

	dst = append(dst, buf[i:]...)
	return dst
}
