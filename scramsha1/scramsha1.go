// Package scramsha1 implements the client and server portions of
// RFC5802 (https://tools.ietf.org/html/rfc5802).
package scramsha1

import (
	hmaclib "crypto/hmac"
	"crypto/sha1"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// ScramSha1 mechanism name.
const MechName = "SCRAM-SHA-1"

// GenerateKeys generates all the keys needed for the mechanism.
func GenerateKeys(password string, salt []byte, iterations uint16) (clientKey []byte, storedKey []byte, serverKey []byte) {
	// TODO: implement pbkdf2 locally to not need a dependency
	saltedPassword := pbkdf2.Key([]byte(password), salt, int(iterations), 20, sha1.New)
	clientKey = hmac(saltedPassword, "Client Key")
	storedKey = h(clientKey)
	serverKey = hmac(saltedPassword, "Server Key")
	return
}

func generateNonce(length uint16, source io.Reader) ([]byte, error) {
	nonceTemp := make([]byte, length*4)
	nonce := make([]byte, length)
	idx := 0
	for {
		n, err := source.Read(nonceTemp)
		if err != nil {
			return nil, err
		}

		for i := 0; i < n; i++ {
			if nonceTemp[i] <= 32 || nonceTemp[i] >= 127 || nonceTemp[i] == 44 {
				continue
			}
			nonce[idx] = nonceTemp[i]
			idx++
			if idx == int(length) {
				return nonce, nil
			}
		}
	}
}

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
