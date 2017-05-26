// +build gssapi
// +build windows linux darwin

package gssapi

import (
	"context"
	"fmt"

	"github.com/craiggwilson/go-sasl/gssapi/internal"
)

// NewClientMech creates a ClientMech to act as the client side of
// ).
func NewClientMech(cfg *ClientConfig) *ClientMech {
	return &ClientMech{
		cfg: cfg,
	}
}

// ClientMech implements the client side portion of ANONYMOUS.
type ClientMech struct {
	cfg *ClientConfig

	// state
	cred *internal.Cred
	ctx  *internal.Ctx

	step int
}

func (m *ClientMech) Close() {
	m.ctx.Delete()
	m.cred.Release()
}

// Start initializes the mechanism and begins the authentication exchange.
func (m *ClientMech) Start(ctx context.Context) (string, []byte, error) {

	var err error
	m.cred, err = internal.AcquireCred(m.cfg.Username, m.cfg.Password, internal.NTUserName, internal.Initiate)
	if err != nil {
		return MechName, nil, err
	}

	return MechName, []byte{}, err
}

// Next continues the exchange.
func (m *ClientMech) Next(ctx context.Context, challenge []byte) ([]byte, error) {
	switch m.step {
	case 0:
		return m.initSecContext(ctx, challenge)
	case 1:
		return m.sendAuthz(ctx, challenge)
	case 2:
		m.step++
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected challenge")
	}
}

// Completed indicates if the authentication exchange is complete from
// the client's perspective.
func (m *ClientMech) Completed() bool {
	return m.step > 2
}

func (m *ClientMech) initSecContext(_ context.Context, challenge []byte) ([]byte, error) {
	if m.ctx == nil {
		m.ctx = internal.NewCtx(
			m.cred,
			fmt.Sprintf("%s@%s", m.cfg.ServiceName, m.cfg.ServiceFQDN),
			m.cfg.Delegate,
		)
	}

	response, err := m.ctx.Init(challenge)
	if err != nil {
		return nil, err
	}

	if m.ctx.Complete() {
		m.step++
	}

	return response, nil
}

func (m *ClientMech) sendAuthz(_ context.Context, challenge []byte) ([]byte, error) {
	// unwrap challenge???

	name, err := m.cred.Name()
	if err != nil {
		return nil, err
	}
	bytes := append([]byte{1, 0, 0, 0}, []byte(name)...)
	response, err := m.ctx.WrapMessage(bytes)
	if err != nil {
		return nil, err
	}

	m.step++
	return response, nil
}
