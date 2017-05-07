package sasl_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/craiggwilson/go-sasl"
)

func TestPlainMech(t *testing.T) {

	verifier := func(_ context.Context, authz, username, password string) error {
		if username == "jack" && password == "mcjack" {
			if authz == "" || authz == "jane" {
				return nil
			}

			return fmt.Errorf("cannot impersonate '%s'", authz)
		}

		return errors.New("invalid username or password")
	}

	tests := []struct {
		authz     string
		username  string
		password  string
		clientErr string
		serverErr string
	}{
		{"", "jack", "mcjack", "", ""},
		{"jane", "jack", "mcjack", "", ""},
		{"", "jack", "mcjac", "context canceled", "sasl mechanism PLAIN: unable to start exchange: invalid username or password"},
		{"joe", "jack", "mcjack", "context canceled", "sasl mechanism PLAIN: unable to start exchange: cannot impersonate 'joe'"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s:%s:%s", test.authz, test.username, test.password), func(t *testing.T) {
			runClientServerTest(t, &clientServerTest{
				client:    sasl.NewPlainClientMech(test.authz, test.username, test.password),
				server:    sasl.NewPlainServerMech(verifier),
				clientErr: test.clientErr,
				serverErr: test.serverErr,
			})
		})
	}
}
