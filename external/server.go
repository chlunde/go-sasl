package external

import (
	"context"
	"fmt"
)

// Verifier verifies the client's authorization identity.
type Verifier func(ctx context.Context, authz string) error

// NewServerMech creates a ServerMech.
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

	return nil, m.verifier(ctx, string(response))
}

// Completed indicates if the authentication exchange is complete from
// the server's perspective.
func (m *ServerMech) Completed() bool {
	return m.done
}
