// Package sasl implements RFC4422(https://tools.ietf.org/html/rfc4422). It provides
// high-level methods to conduct an authentication exchange as both a server and as
// a client, and provides implementations of different sasl mechanisms to use.
package sasl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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

func newError(msg string, inner error) *Error {
	return &Error{
		Msg:   msg,
		Inner: inner,
	}
}

var errUnexpectedChallenge = errors.New("unexpected challenge")
var errUnexpectedResponse = errors.New("unexpected response")

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

// AuthCallback passes data to the transport and receives the next piece.
type AuthCallback func([]byte) ([]byte, error)

// ConverseAsClient conducts an authentication exchange as a client.
func ConverseAsClient(ctx context.Context, mech ClientMech, incoming, outgoing chan []byte) error {
	fmt.Println("starting client")
	mechName, response, err := mech.Start(ctx)
	if err != nil {
		return newError(fmt.Sprintf("sasl mechanism %s: unable to start exchange", mechName), err)
	}

	var challenge []byte
	for {
		fmt.Println("client sending: ", response)
		select {
		case outgoing <- response:
		case <-ctx.Done():
			return newError(fmt.Sprintf("sasl mechanism %s: failed to send response", mechName), ctx.Err())
		}

		select {
		case challenge = <-incoming:
		case <-ctx.Done():
			return newError(fmt.Sprintf("sasl mechanism %s: failed to receive challenge", mechName), ctx.Err())
		}

		fmt.Println("client received: ", challenge)
		response, err = mech.Next(ctx, challenge)
		if err != nil {
			return newError(fmt.Sprintf("sasl mechanism %s: client failed to provide response", mechName), err)
		}

		if mech.Completed() {
			break
		}
	}
	fmt.Println("client complete")

	return nil
}

// ConverseAsServer conducts an authentication exchange as a server.
func ConverseAsServer(ctx context.Context, mech ServerMech, response []byte, incoming, outgoing chan []byte) error {
	fmt.Println("starting server")
	fmt.Println("server received: ", response)
	mechName, challenge, err := mech.Start(ctx, response)
	if err != nil {
		return newError(fmt.Sprintf("sasl mechanism %s: unable to start exchange", mechName), err)
	}

	for {
		fmt.Println("server sending: ", challenge)
		select {
		case outgoing <- challenge:
		case <-ctx.Done():
			return newError(fmt.Sprintf("sasl mechanism %s: failed to send challenge", mechName), ctx.Err())
		}

		if mech.Completed() {
			break
		}

		select {
		case response = <-incoming:
		case <-ctx.Done():
			return newError(fmt.Sprintf("sasl mechanism %s: failed to receive response", mechName), ctx.Err())
		}

		fmt.Println("server received: ", response)
		challenge, err = mech.Next(ctx, response)
		if err != nil {
			return newError(fmt.Sprintf("sasl mechanism %s: server failed to provide challenge", mechName), err)
		}
	}
	fmt.Println("server complete")

	return nil
}

func readAll(r io.Reader) ([]byte, error) {
	return ioutil.ReadAll(r)
}

func writeAll(w io.Writer, b []byte) error {
	t := 0
	var n int
	var err error
	for {
		n, err = w.Write(b)
		if err != nil {
			return err
		}
		t += n
		if t >= n {
			return nil
		}

		b = b[n:]
	}
}
