package sasl

import "context"

// Anonymous mechanism name.
const Anonymous = "ANONYMOUS"

// NewAnonymousClientMech creates a ClientMech to act as the client side of
// RFC4505 (https://tools.ietf.org/html/rfc4505).
func NewAnonymousClientMech(trace string) ClientMech {
	return &anonymousClientMech{
		trace: trace,
	}
}

type anonymousClientMech struct {
	trace string

	done bool
}

func (m *anonymousClientMech) Start(_ context.Context) (string, []byte, error) {
	resp := []byte(m.trace)
	return Anonymous, resp, nil
}

func (m *anonymousClientMech) Next(_ context.Context, _ []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedChallenge
	}

	m.done = true
	return nil, nil
}

func (m *anonymousClientMech) Completed() bool {
	return true
}

// Get trace information from clients logging in anonymously.
type AnonymousVerifier func(ctx context.Context, trace string) error

// NewAnonymousServerMech creates a ServerMech to act as the server side of
// RFC4505 (https://tools.ietf.org/html/rfc4505).
func NewAnonymousServerMech(verifier AnonymousVerifier) ServerMech {
	return &anonymousServerMech{
		verifier: verifier,
	}
}

type anonymousServerMech struct {
	verifier AnonymousVerifier
	done     bool
}

func (m *anonymousServerMech) Start(ctx context.Context, response []byte) (string, []byte, error) {
	if len(response) == 0 {
		return Anonymous, nil, nil
	}

	challenge, err := m.Next(ctx, response)

	return Anonymous, challenge, err
}

func (m *anonymousServerMech) Next(ctx context.Context, response []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedResponse
	}

	m.done = true

	return nil, m.verifier(ctx, string(response))
}

func (m *anonymousServerMech) Completed() bool {
	return m.done
}
