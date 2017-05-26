// +build gssapi,!windows,!linux,!darwin

package gssapi

import (
	"context"
	"fmt"
	"runtime"
)

// NewClientMech creates a ClientMech.
func NewClientMech(cfg *ClientConfig) *ClientMech {
	return &ClientMech{}
}

// ClientMech implements the client side portion of GSSAPI. GSSAPI
// is not supported on this platform and will error upon use.
type ClientMech struct{}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start(ctx context.Context) (string, []byte, error) {
	return MechName, nil, fmt.Errorf("GSSAPI is not supported on %s", runtime.GOOS)
}

// Next continues the exchange.
func (m *ClientMech) Next(_ context.Context, challenge []byte) ([]byte, error) {
	return nil, fmt.Errorf("GSSAPI is not supported on %s", runtime.GOOS)
}

// Completed indicates if the authentication exchange is complete from
// the client's perspective.
func (m *ClientMech) Completed() bool {
	return false
}
