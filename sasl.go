// Package sasl implements the framework for RFC4422(https://tools.ietf.org/html/rfc4422).
// It provides high-level methods to conduct an authentication exchange as both a server
// and as a client. Mechanism implementations are defined in other packages.
package sasl

import (
	"context"
	"fmt"
)

// ClientMech handles authenticating with a server.
type ClientMech interface {
	// Start initializes the mechanism and begins the authentication exchange.
	Start(context.Context) (string, []byte, error)

	// Next continues the exchange.
	Next(context.Context, []byte) ([]byte, error)

	// Completed indicates if the authentication exchange is complete from
	// the client's perspective.
	Completed() bool
}

// ServerMech handles authenticating with a client.
type ServerMech interface {
	// Start initializes the mechanism and begins the authentication exchange.
	Start(context.Context, []byte) (string, []byte, error)

	// Next continues the exchange.
	Next(context.Context, []byte) ([]byte, error)

	// Completed indicates if the authentication exchange is complete from
	// the server's perspective.
	Completed() bool
}

// ConverseAsClient conducts an authentication exchange as a client.
func ConverseAsClient(ctx context.Context, mech ClientMech, incoming <-chan []byte, outgoing chan<- []byte) error {
	mechName, response, err := mech.Start(ctx)
	if err != nil {
		return newError(fmt.Sprintf("sasl mechanism %s: unable to start exchange", mechName), err)
	}

	var challenge []byte
	for {
		select {
		case outgoing <- response:
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case challenge = <-incoming:
		case <-ctx.Done():
			return ctx.Err()
		}

		response, err = mech.Next(ctx, challenge)
		if err != nil {
			if response != nil {
				// some mechanisms communicate errors via the mechanism. In these cases,
				// we can expect an error as well as an non-nil response.
				select {
				case outgoing <- response:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return newError(fmt.Sprintf("sasl mechanism %s: client failed to provide response", mechName), err)
		}

		if mech.Completed() {
			break
		}
	}

	return nil
}

// ConverseAsServer conducts an authentication exchange as a server.
func ConverseAsServer(ctx context.Context, mech ServerMech, response []byte, incoming <-chan []byte, outgoing chan<- []byte) error {
	mechName, challenge, err := mech.Start(ctx, response)
	if err != nil {
		return newError(fmt.Sprintf("sasl mechanism %s: unable to start exchange", mechName), err)
	}

	for {
		select {
		case outgoing <- challenge:
		case <-ctx.Done():
			return ctx.Err()
		}

		if mech.Completed() {
			break
		}

		select {
		case response = <-incoming:
		case <-ctx.Done():
			return ctx.Err()
		}

		challenge, err = mech.Next(ctx, response)
		if err != nil {
			if challenge != nil {
				// some mechanisms communicate errors via the mechanism. In these cases,
				// we can expect an error as well as an non-nil challenge.
				select {
				case outgoing <- challenge:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return newError(fmt.Sprintf("sasl mechanism %s: server failed to provide challenge", mechName), err)
		}
	}

	return nil
}

func newError(msg string, inner error) *Error {
	return &Error{
		Msg:   msg,
		Inner: inner,
	}
}

// Error is always the type of error returned from ConverseAsClient and
// ConverseAsServer.
type Error struct {
	Msg   string
	Inner error
}

func (e *Error) Error() string {
	s := e.Msg
	if e.Inner != nil {
		s += ": " + e.Inner.Error()
	}
	return s
}
