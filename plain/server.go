package plain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// AuthzVerifier verifies the client's authorization identity.
type AuthzVerifier func(ctx context.Context, username, authz string) error

// UserPassVerifier verifies the client's credentials.
type UserPassVerifier func(ctx context.Context, username, password string) error

// NewServerMech creates a ServerMech to act as the server side of
// RFC4616 (https://tools.ietf.org/html/rfc4616).
func NewServerMech(userPassVerifier UserPassVerifier, authzVerifier AuthzVerifier) *ServerMech {
	return &ServerMech{
		userPassVerifier: userPassVerifier,
		authzVerifier:    authzVerifier,
	}
}

// ServerMech implements the server side portion of ANONYMOUS.
type ServerMech struct {
	Authz    string
	Username string
	Password string

	authzVerifier    AuthzVerifier
	userPassVerifier UserPassVerifier

	// state
	done bool
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ServerMech) Start(ctx context.Context, response []byte) (string, []byte, error) {
	if len(response) == 0 {
		return MechName, nil, nil
	}

	challenge, err := m.Next(ctx, response)

	return MechName, challenge, err
}

// Next continues the exchange.
func (m *ServerMech) Next(ctx context.Context, response []byte) ([]byte, error) {
	if m.done {
		return nil, fmt.Errorf("unexpected response")
	}

	m.done = true

	parts := bytes.Split(response, []byte("\x00"))
	if len(parts) != 3 {
		return nil, errors.New("invalid response")
	}

	m.Authz = string(parts[0])
	m.Username = string(parts[1])
	m.Password = string(parts[2])

	var err error
	if m.userPassVerifier != nil {
		err = m.userPassVerifier(ctx, m.Username, m.Password)
	}
	if err == nil && m.authzVerifier != nil {
		err = m.authzVerifier(ctx, m.Username, m.Authz)
	}

	return []byte{}, err
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.done
}
