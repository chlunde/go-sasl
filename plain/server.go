package plain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// Verifier verifies the client's credentials.
type Verifier func(ctx context.Context, authz, username, password string) error

// NewServerMech creates a ServerMech to act as the server side of
// RFC4616 (https://tools.ietf.org/html/rfc4616).
func NewServerMech(verifier Verifier) *ServerMech {
	return &ServerMech{
		verifier: verifier,
	}
}

// ServerMech implements the server side portion of ANONYMOUS.
type ServerMech struct {
	verifier Verifier

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

	authz := string(parts[0])
	username := string(parts[1])
	password := string(parts[2])

	return nil, m.verifier(ctx, authz, username, password)
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.done
}
