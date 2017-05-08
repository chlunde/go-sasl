package testhelpers

import (
	"context"
	"testing"

	"github.com/craiggwilson/go-sasl"
)

// RunClientServerTest executes the client and the server together.
func RunClientServerTest(t *testing.T, client sasl.ClientMech, server sasl.ServerMech, expectedClientErr, expectedServerErr string) {
	clientErr, serverErr := runConversation(client, server)
	verifyError(t, "client", expectedClientErr, clientErr)
	verifyError(t, "server", expectedServerErr, serverErr)
}

func runConversation(client sasl.ClientMech, server sasl.ServerMech) (error, error) {
	messages := make(chan []byte, 1)

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	cancelCtx, cancel := context.WithCancel(context.Background())

	go func() {
		err := sasl.ConverseAsClient(cancelCtx, client, messages, messages)
		if err != nil {
			cancel()
		}
		clientErr <- err
	}()

	go func() {
		var err error
		select {
		case b := <-messages:
			err = sasl.ConverseAsServer(cancelCtx, server, b, messages, messages)
			if err != nil {
				cancel()
			}
		case <-cancelCtx.Done():
			err = cancelCtx.Err()
		}
		serverErr <- err
	}()

	cerr := <-clientErr
	serr := <-serverErr
	cancel()

	return cerr, serr
}

func verifyError(t *testing.T, errKind string, expected string, actual error) {
	if expected != "" {
		if actual == nil {
			t.Fatalf("expected a %s error, but got none", errKind)
		} else if expected != actual.Error() {
			t.Fatalf("expected %s error to be '%s', but got '%v'", errKind, expected, actual.Error())
		}
	} else if actual != nil {
		t.Fatalf("expected no %s error, but got '%v'", errKind, actual.Error())
	}
}
