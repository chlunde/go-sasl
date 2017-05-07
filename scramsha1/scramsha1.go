// Package scramsha1 implements the client and server portions of
// RFC5802 (https://tools.ietf.org/html/rfc5802).

package scramsha1

import (
	hmaclib "crypto/hmac"
	"crypto/sha1"
	"io"
)

// ScramSha1 mechanism name.
const ScramSha1 = "SCRAM-SHA-1"

func h(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmac(data []byte, key string) []byte {
	h := hmaclib.New(sha1.New, data)
	io.WriteString(h, key)
	return h.Sum(nil)
}

func xor(a []byte, b []byte) []byte {
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
