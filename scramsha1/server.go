package scramsha1

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
)

// NewServerMech creates a new ServerMech.
func NewServerMech(storedUserProvider StoredUserProvider, nonceLen uint16, nonceSource io.Reader) *ServerMech {
	return &ServerMech{
		storedUserProvider: storedUserProvider,
		nonceLen:           nonceLen,
		nonceSource:        nonceSource,
	}
}

// StoredUser holds the information needed to validate a user.
type StoredUser struct {
	Salt       []byte
	Iterations uint16
	StoredKey  []byte
	ServerKey  []byte
}

// StoredUserProvider returns the salt and iteration count for a given user.
type StoredUserProvider func(ctx context.Context, username string) (*StoredUser, error)

// ServerMech implements the server side portion of SCRAM-SHA-1.
type ServerMech struct {
	Username string
	Authz    string

	storedUserProvider StoredUserProvider
	nonceLen           uint16
	nonceSource        io.Reader

	// state
	step       uint8
	storedUser *StoredUser

	nonce                  string
	clientFirstMessageBare string
	serverFirstMessage     string
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ServerMech) Start(ctx context.Context, initialResponse []byte) (string, []byte, error) {
	if len(initialResponse) == 0 {
		return ScramSha1, nil, nil
	}

	challenge, err := m.Next(ctx, initialResponse)
	return ScramSha1, challenge, err
}

// Next continues the exchange.
func (m *ServerMech) Next(ctx context.Context, response []byte) ([]byte, error) {
	m.step++
	switch m.step {
	case 1:
		return m.step1(ctx, response)
	case 2:
		return m.step2(ctx, response)
	default:
		return nil, fmt.Errorf("unexpected response")
	}

	return nil, nil
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.step >= 2
}

func (m *ServerMech) step1(ctx context.Context, response []byte) ([]byte, error) {
	fields := bytes.Split(response, []byte{','})

	if len(fields[0]) != 1 {
		return nil, fmt.Errorf("invalid initial response")
	}

	if fields[0][0] != 'n' && fields[0][0] != 'y' {
		return nil, fmt.Errorf("invalid initial response: expected p, n, or y")
	}

	if bytes.HasPrefix(fields[1], []byte("a=")) {
		m.Authz = string(fields[1][2:])
	}

	if !bytes.HasPrefix(fields[2], []byte("n=")) {
		return nil, fmt.Errorf("invalid initial response: expected username")
	}
	m.Username = string(fields[2][2:])

	if !bytes.HasPrefix(fields[3], []byte("r=")) {
		return nil, fmt.Errorf("invalid initial response: expected nonce")
	}
	clientNonce := fields[3][2:]

	m.clientFirstMessageBare = string(fields[2]) + "," + string(fields[3])

	serverNonce, err := generateNonce(m.nonceLen, m.nonceSource)
	if err != nil {
		return nil, fmt.Errorf("unable to generate nonce of length %d: %v", m.nonceLen, err)
	}

	m.storedUser, err = m.storedUserProvider(ctx, m.Username)
	if err != nil {
		return nil, fmt.Errorf("could not get salt and iteration count for user '%s'", m.Username)
	}

	m.nonce = "r=" + string(clientNonce) + string(serverNonce)
	fmt.Println(m.nonce)
	salt := "s=" + base64.StdEncoding.EncodeToString(m.storedUser.Salt)
	iterationCount := "i=" + strconv.Itoa(int(m.storedUser.Iterations))

	m.serverFirstMessage = m.nonce + "," + salt + "," + iterationCount

	return []byte(m.serverFirstMessage), nil
}

func (m *ServerMech) step2(ctx context.Context, response []byte) ([]byte, error) {
	fields := bytes.Split(response, []byte{','})
	e := []byte("e=other-error")
	if len(fields) < 3 {
		return e, fmt.Errorf("invalid response")
	}

	if !bytes.HasPrefix(fields[0], []byte("c=")) {
		return e, fmt.Errorf("invalid response: expected channel bindings")
	}
	// TODO: does this need to be validated?
	channelBinding := string(fields[0])

	if !bytes.HasPrefix(fields[1], []byte("r=")) {
		return e, fmt.Errorf("invalid response: expected nonce")
	}
	nonce := string(fields[1])
	if m.nonce != nonce {
		return e, fmt.Errorf("invalid response: nonce mismatch")
	}

	idx := 2
	for idx < len(fields) && !bytes.HasPrefix(fields[idx], []byte("p=")) {
		// ignore extensions
		idx++
	}

	if idx >= len(fields) {
		return e, fmt.Errorf("invalid response: expected proof")
	}

	p := make([]byte, base64.StdEncoding.DecodedLen(len(fields[idx][2:])))
	n, err := base64.StdEncoding.Decode(p, fields[idx][2:])
	if err != nil {
		return e, fmt.Errorf("invalid response: invalid proof")
	}
	p = p[:n]

	clientFinalMessageWithoutProof := channelBinding + "," + m.nonce
	authMessage := m.clientFirstMessageBare + "," + m.serverFirstMessage + "," + clientFinalMessageWithoutProof
	clientSignature := hmac(m.storedUser.StoredKey, authMessage)
	clientKey := xor(p, clientSignature)
	storedKey := h(clientKey)

	if !bytes.Equal(storedKey, m.storedUser.StoredKey) {
		return e, fmt.Errorf("invalid response: client key mismatch")
	}

	serverSignature := hmac(m.storedUser.ServerKey, authMessage)
	v := "v=" + base64.StdEncoding.EncodeToString(serverSignature)
	return []byte(v), nil
}
