package scramsha1

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var usernameSanitizer = strings.NewReplacer("=", "=3D", ",", "=2D")

// NewClientMech creates a new ClientMech.
func NewClientMech(authz, username, password string, nonceLen uint16, nonceSource io.Reader) *ClientMech {
	return &ClientMech{
		authz:       authz,
		username:    username,
		password:    password,
		nonceLen:    nonceLen,
		nonceSource: nonceSource,
	}
}

// ClientMech implements the client side portion of SCRAM-SHA-1.
type ClientMech struct {
	authz       string
	username    string
	password    string
	nonceLen    uint16
	nonceSource io.Reader

	// state
	step                   uint8
	clientNonce            []byte
	clientFirstMessageBare string
	serverSignature        []byte
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start(_ context.Context) (string, []byte, error) {
	var err error
	m.clientNonce, err = generateNonce(m.nonceLen, m.nonceSource)
	if err != nil {
		return MechName, nil, fmt.Errorf("unable to generate nonce of length %d: %v", m.nonceLen, err)
	}

	gs2header := "n,"
	if m.authz != "" {
		gs2header += "a=" + m.authz
	}
	gs2header += ","

	m.clientFirstMessageBare = "n=" + usernameSanitizer.Replace(m.username) + ",r=" + string(m.clientNonce)

	clientFirstMessage := gs2header + m.clientFirstMessageBare

	return MechName, []byte(clientFirstMessage), nil
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
		return nil, fmt.Errorf("unexpected challenge")
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
	clientKey, storedKey, serverKey := GenerateKeys(m.password, s, uint16(i))

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
