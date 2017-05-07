package sasl_test

import (
	"context"
	"testing"

	"github.com/craiggwilson/go-sasl"
)

type clientServerTest struct {
	client    sasl.ClientMech
	server    sasl.ServerMech
	clientErr string
	serverErr string
}

func runClientServerTest(t *testing.T, test *clientServerTest) {
	clientErr, serverErr := runConversation(test.client, test.server)
	verifyError(t, "client", test.clientErr, clientErr)
	verifyError(t, "server", test.serverErr, serverErr)
}

func runConversation(client sasl.ClientMech, server sasl.ServerMech) (error, error) {
	clientToServer := make(chan []byte, 1)
	serverToClient := make(chan []byte, 1)

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	cancelCtx, cancel := context.WithCancel(context.Background())

	go func() {
		err := sasl.ConverseAsClient(cancelCtx, client, serverToClient, clientToServer)
		if err != nil {
			cancel()
		}
		clientErr <- err
	}()

	go func() {
		var err error
		select {
		case b := <-clientToServer:
			err = sasl.ConverseAsServer(cancelCtx, server, b, clientToServer, serverToClient)
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
