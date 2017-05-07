package scramsha1

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var usernameSanitizer = strings.NewReplacer("=", "=3D", ",", "=2D")

type ClientConfig struct {
	NonceLen    uint16
	NonceSource io.Reader
}

// NewClientMech creates a new ClientMech.
func NewClientMech(authz, username, password string, cfg *ClientConfig) *ClientMech {

	if cfg == nil {
		cfg = &ClientConfig{}
	}

	if cfg.NonceLen == 0 {
		cfg.NonceLen = 16
	}
	if cfg.NonceSource == nil {
		// TODO: get default nonce source
	}

	return &ClientMech{
		authz:    authz,
		username: username,
		password: password,
		cfg:      cfg,
	}
}

// ClientMech implements the client side portion of SCRAM-SHA-1.
type ClientMech struct {
	authz    string
	username string
	password string
	cfg      *ClientConfig

	// state
	step                   uint8
	clientNonce            []byte
	clientFirstMessageBare string
	serverSignature        []byte
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start() (string, []byte, error) {
	m.clientNonce = make([]byte, m.cfg.NonceLen)
	tn := uint16(0)
	for tn < m.cfg.NonceLen {
		n, err := m.cfg.NonceSource.Read(m.clientNonce)
		if err != nil {
			return ScramSha1, nil, fmt.Errorf("could not generate nonce of length %d: %v", m.cfg.NonceLen, err)
		}
		tn += uint16(n)
	}

	gs2header := "n,"

	if m.authz != "" {
		gs2header += "a=" + m.authz
	} else {
		gs2header += ","
	}

	m.clientFirstMessageBare = "n=" + usernameSanitizer.Replace(m.username) + ",r=" + string(m.clientNonce)

	clientFirstMessage := gs2header + m.clientFirstMessageBare

	return ScramSha1, []byte(clientFirstMessage), nil
}

// Next continues the exchange.
func (m *ClientMech) Next(ctx context.Context, challenge []byte) ([]byte, error) {
	m.step++
	switch m.step {
	case 1:
		return m.step1(ctx, challenge)
	case 2:
		return m.step2(ctx, challenge)
	default:
		return nil, fmt.Errorf("unexpected server challenge")
	}
}

// Completed indicates if the authentication exchange is complete from
// the client's perspective.
func (m *ClientMech) Completed() bool {
	return m.step >= 2
}

func (m *ClientMech) step1(ctx context.Context, challenge []byte) ([]byte, error) {
	fields := bytes.Split(challenge, []byte{','})
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid challenge")
	}

	if !bytes.HasPrefix(fields[0], []byte("r=")) {
		return nil, fmt.Errorf("invalid challenge: expected nonce")
	}
	r := fields[0][2:]
	if !bytes.HasPrefix(r, m.clientNonce) {
		return nil, fmt.Errorf("invalid challenge: nonce mismatch")
	}

	if !bytes.HasPrefix(fields[1], []byte("s=")) {
		return nil, fmt.Errorf("invalid challenge: expected salt")
	}
	s := make([]byte, base64.StdEncoding.DecodedLen(len(fields[1][2:])))
	n, err := base64.StdEncoding.Decode(s, fields[1][2:])
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: invalid salt")
	}
	s = s[:n]

	if !bytes.HasPrefix(fields[2], []byte("i=")) {
		return nil, fmt.Errorf("invalid challenge: expected iteration-count")
	}
	i, err := strconv.Atoi(string(fields[2][2:]))
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: invalid iteration-count")
	}

	const channelBinding = "c=biws" // base64 of gs2-channel-binding

	clientFinalMessageWithoutProof := channelBinding + ",r=" + string(r)
	authMessage := m.clientFirstMessageBare + "," + string(challenge) + "," + clientFinalMessageWithoutProof

	// TODO: it's possible to cache the stored key and server key
	// TODO: implement pbkdf2 locally to not need a dependency
	saltedPassword := pbkdf2.Key([]byte(m.password), s, i, 20, sha1.New)
	serverKey := hmac(saltedPassword, "Server Key")
	clientKey := hmac(saltedPassword, "Client Key")
	storedKey := h(clientKey)

	clientSignature := hmac(storedKey, authMessage)
	m.serverSignature = hmac(serverKey, authMessage)

	clientProof := xor(clientKey, clientSignature)
	proof := "p=" + base64.StdEncoding.EncodeToString(clientProof)

	clientFinalMessage := clientFinalMessageWithoutProof + "," + proof

	return []byte(clientFinalMessage), nil
}

func (m *ClientMech) step2(ctx context.Context, challenge []byte) ([]byte, error) {
	fields := bytes.Split(challenge, []byte{','})
	if bytes.HasPrefix(fields[0], []byte("e=")) {
		return nil, fmt.Errorf(string(fields[0][2:]))
	}

	if !bytes.HasPrefix(fields[0], []byte("v=")) {
		return nil, fmt.Errorf("invalid challenge: expected server signature")
	}

	v := make([]byte, base64.StdEncoding.DecodedLen(len(fields[0][2:])))
	n, err := base64.StdEncoding.Decode(v, fields[0][2:])
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: invalid server verification")
	}
	v = v[:n]

	if !bytes.Equal(m.serverSignature, v) {
		return nil, fmt.Errorf("invalid challenge: server signature mismatch")
	}

	return nil, nil
}
