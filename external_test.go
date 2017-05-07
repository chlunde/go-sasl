package sasl_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/craiggwilson/go-sasl"
)

func TestExternalMech(t *testing.T) {

	verifier := func(_ context.Context, authz string) error {

		if authz == "jack" {
			return nil
		}

		return errors.New("invalid credentials")
	}

	tests := []struct {
		authz     string
		clientErr string
		serverErr string
	}{
		{"jack", "", ""},
		{"jane", "sasl mechanism EXTERNAL: failed to receive challenge: context canceled", "sasl mechanism EXTERNAL: unable to start exchange: invalid credentials"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.authz), func(t *testing.T) {
			runClientServerTest(t, &clientServerTest{
				client:    sasl.NewExternalClientMech(test.authz),
				server:    sasl.NewExternalServerMech(verifier),
				clientErr: test.clientErr,
				serverErr: test.serverErr,
			})
		})
	}
}
