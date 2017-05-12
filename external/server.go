package external

import (
	"context"
	"fmt"
)

// AuthzVerifier verifies the client's authorization identity.
type AuthzVerifier func(ctx context.Context, authz string) error

// NewServerMech creates a ServerMech.
func NewServerMech(verifier AuthzVerifier) *ServerMech {
	return &ServerMech{
		verifier: verifier,
	}
}

// ServerMech implements the server side portion of ANONYMOUS.
type ServerMech struct {
	Authz string

	verifier AuthzVerifier

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

	m.Authz = string(response)

	var err error
	if m.verifier != nil {
		err = m.verifier(ctx, m.Authz)
	}

	return []byte{}, err
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.done
}
