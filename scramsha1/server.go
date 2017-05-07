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
	if nonceLen == 0 {
		nonceLen = 16
	}

	if nonceSource == nil {
		// TODO: get default nonce source
	}

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
	ClientKey  []byte
	ServerKey  []byte
}

// StoredUserProvider returns the salt and iteration count for a given user.
type StoredUserProvider func(ctx context.Context, username string) (*StoredUser, error)

// UserInfo holds the user information from the client.
type UserInfo struct {
	Authz    string
	Username string
}

// ServerMech implements the server side portion of SCRAM-SHA-1.
type ServerMech struct {
	storedUserProvider StoredUserProvider
	nonceLen           uint16
	nonceSource        io.Reader

	// state
	step       uint8
	userInfo   *UserInfo
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
	}

	return nil, nil
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.step >= 2
}

// UserInfo is the information of the user provided by the client.
func (m *ServerMech) UserInfo() *UserInfo {
	return m.userInfo
}

func (m *ServerMech) step1(ctx context.Context, response []byte) ([]byte, error) {
	fields := bytes.Split(response, []byte{','})

	if len(fields[0]) != 1 {
		return nil, fmt.Errorf("invalid initial response")
	}
	gs2cbindFlag := fields[0][0]
	if gs2cbindFlag != 'n' && gs2cbindFlag != 'y' {
		return nil, fmt.Errorf("server does not support channel binding")
	}

	m.userInfo = &UserInfo{}

	if bytes.HasPrefix(fields[1], []byte("a=")) {
		m.userInfo.Authz = string(fields[1][2:])
	}

	if !bytes.HasPrefix(fields[2], []byte("n=")) {
		return nil, fmt.Errorf("invalid initial response: expected username")
	}
	m.userInfo.Username = string(fields[2][2:])

	if !bytes.HasPrefix(fields[3], []byte("r=")) {
		return nil, fmt.Errorf("invalid initial response: expected nonce")
	}
	clientNonce := fields[3][2:]

	serverNonce := make([]byte, m.nonceLen)
	tn := uint16(0)
	for tn < m.nonceLen {
		n, err := m.nonceSource.Read(serverNonce)
		if err != nil {
			return nil, fmt.Errorf("could not generate nonce of length %d: %v", m.nonceLen, err)
		}
		tn += uint16(n)
	}

	var err error
	m.storedUser, err = m.storedUserProvider(ctx, m.userInfo.Username)
	if err != nil {
		return nil, fmt.Errorf("could not get salt and iteration count for user '%s'", m.userInfo.Username)
	}

	m.nonce = "r=" + string(clientNonce) + string(serverNonce)
	salt := "s=" + base64.StdEncoding.EncodeToString(m.storedUser.Salt)
	iterationCount := "i=" + strconv.Itoa(int(m.storedUser.Iterations))

	m.serverFirstMessage = m.nonce + "," + salt + "," + iterationCount

	return []byte(m.serverFirstMessage), nil
}

func (m *ServerMech) step2(ctx context.Context, response []byte) ([]byte, error) {
	fields := bytes.Split(response, []byte{','})
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid response")
	}

	if !bytes.HasPrefix(fields[0], []byte("c=")) {
		return nil, fmt.Errorf("invalid response: expected channel bindings")
	}
	// TODO: does this need to be validated?
	channelBinding := string(fields[0][2:])

	if !bytes.HasPrefix(fields[1], []byte("r=")) {
		return nil, fmt.Errorf("invalid response: expected nonce")
	}
	nonce := string(fields[1])
	if m.nonce != nonce {
		return nil, fmt.Errorf("invalid response: nonce mismatch")
	}

	idx := 2
	for idx < len(fields) && !bytes.HasPrefix(fields[idx], []byte("p=")) {
		// ignore extensions
		idx++
	}

	if idx >= len(fields) {
		return nil, fmt.Errorf("invalid response: expected proof")
	}

	p := make([]byte, base64.StdEncoding.DecodedLen(len(fields[idx][2:])))
	n, err := base64.StdEncoding.Decode(p, fields[idx][2:])
	if err != nil {
		return nil, fmt.Errorf("invalid response: invalid proof")
	}
	p = p[:n]

	clientFinalMessageWithoutProof := channelBinding + "," + m.nonce
	authMessage := m.clientFirstMessageBare + "," + m.serverFirstMessage + "," + clientFinalMessageWithoutProof

	storedKey := h(m.storedUser.ClientKey)

	clientSignature := hmac(storedKey, authMessage)
	clientProof := xor(m.storedUser.ClientKey, clientSignature)

	if !bytes.Equal(p, clientProof) {
		return nil, fmt.Errorf("invalid challenge: proof mismatch")
	}

	serverSignature := hmac(m.storedUser.ServerKey, authMessage)

	v := "v=" + base64.StdEncoding.EncodeToString(serverSignature)

	return []byte(v), nil
}
