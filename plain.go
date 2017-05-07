package sasl

import (
	"bytes"
	"context"
	"errors"
)

// Plain mechanism name.
const Plain = "PLAIN"

// NewPlainClientMech creates a ClientMech to act as the client side of
// RFC4616 (https://tools.ietf.org/html/rfc4616).
func NewPlainClientMech(authz, username, password string) ClientMech {
	return &plainClientMech{
		username: username,
		password: password,
		authz:    authz,
	}
}

type plainClientMech struct {
	username string
	password string
	authz    string

	done bool
}

func (m *plainClientMech) Start(_ context.Context) (string, []byte, error) {
	resp := []byte(m.authz + "\x00" + m.username + "\x00" + m.password)
	return Plain, resp, nil
}

func (m *plainClientMech) Next(_ context.Context, _ []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedChallenge
	}

	m.done = true
	return nil, nil
}

func (m *plainClientMech) Completed() bool {
	return true
}

// PlainVerifier verifies the client's credentials.
type PlainVerifier func(ctx context.Context, authz, username, password string) error

// NewPlainServerMech creates a ServerMech to act as the server side of
// RFC4616 (https://tools.ietf.org/html/rfc4616).
func NewPlainServerMech(verifier PlainVerifier) ServerMech {
	return &plainServerMech{
		verifier: verifier,
	}
}

type plainServerMech struct {
	verifier PlainVerifier
	done     bool
}

func (m *plainServerMech) Start(ctx context.Context, response []byte) (string, []byte, error) {
	if len(response) == 0 {
		return Plain, nil, nil
	}

	challenge, err := m.Next(ctx, response)

	return Plain, challenge, err
}

func (m *plainServerMech) Next(ctx context.Context, response []byte) ([]byte, error) {
	if m.done {
		return nil, errUnexpectedResponse
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

func (m *plainServerMech) Completed() bool {
	return m.done
}
