// +build !gssapi

package gssapi

import (
	"context"
	"fmt"
)

// NewClientMech creates a ClientMech.
func NewClientMech(cfg *ClientConfig) *ClientMech {
	return &ClientMech{}
}

// ClientMech implements the client side portion of GSSAPI. GSSAPI
// has not been enabled during the build and will error upon use.
type ClientMech struct{}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start(ctx context.Context) (string, []byte, error) {
	return MechName, nil, fmt.Errorf("GSSAPI support not enabled during build (-tags gssapi)")
}

// Next continues the exchange.
func (m *ClientMech) Next(_ context.Context, challenge []byte) ([]byte, error) {
	return nil, fmt.Errorf("GSSAPI support not enabled during build (-tags gssapi)")
}

// Completed indicates if the authentication exchange is complete from
// the client's perspective.
func (m *ClientMech) Completed() bool {
	return false
}
