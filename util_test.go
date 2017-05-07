package sasl_test

import (
	"context"

	"github.com/craiggwilson/go-sasl"
)

func runClientServerTest(client sasl.ClientMech, server sasl.ServerMech) (error, error) {
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

	return cerr, serr
}
