package anonymous

import (
	"context"
	"fmt"
)

// NewClientMech creates a ClientMech to act as the client side of
// ).
func NewClientMech(trace string) *ClientMech {
	return &ClientMech{
		trace: trace,
	}
}

// ClientMech implements the client side portion of ANONYMOUS.
type ClientMech struct {
	trace string

	// state
	done bool
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start(_ context.Context) (string, []byte, error) {
	resp := []byte(m.trace)
	return MechName, resp, nil
}

// Next continues the exchange.
func (m *ClientMech) Next(_ context.Context, _ []byte) ([]byte, error) {
	if m.done {
		return nil, fmt.Errorf("unexpected challenge")
	}

	m.done = true
	return nil, nil
}

// Completed indicates if the authentication exchange is complete from
// the client's perspective.
func (m *ClientMech) Completed() bool {
	return true
}
