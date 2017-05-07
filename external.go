package sasl

import "context"

// External mechanism name.
const External = "EXTERNAL"

// NewExternalClientMech creates a ClientMech to act as the client side of
// RFC4422 (https://tools.ietf.org/html/rfc4422).
func NewExternalClientMech(authz string) ClientMech {
	return &externalClientMech{
		authz: authz,
	}
}

type externalClientMech struct {
	authz string

	done bool
}

func (m *externalClientMech) Start(_ context.Context) (string, []byte, error) {
	resp := []byte(m.authz)
	return External, resp, nil
}

func (m *externalClientMech) Next(_ context.Context, _ []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedChallenge
	}

	m.done = true
	return nil, nil
}

func (m *externalClientMech) Completed() bool {
	return true
}

// ExternalVerifier verifies the client's authorization identity.
type ExternalVerifier func(ctx context.Context, authz string) error

// NewExternalServerMech creates a ServerMech to act as the server side of
// RFC4422 (https://tools.ietf.org/html/rfc4422).
func NewExternalServerMech(verifier ExternalVerifier) ServerMech {
	return &externalServerMech{
		verifier: verifier,
	}
}

type externalServerMech struct {
	verifier ExternalVerifier
	done     bool
}

func (m *externalServerMech) Start(ctx context.Context, response []byte) (string, []byte, error) {
	if len(response) == 0 {
		return External, nil, nil
	}

	challenge, err := m.Next(ctx, response)

	return External, challenge, err
}

func (m *externalServerMech) Next(ctx context.Context, response []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedResponse
	}

	m.done = true

	return nil, m.verifier(ctx, string(response))
}

func (m *externalServerMech) Completed() bool {
	return m.done
}
