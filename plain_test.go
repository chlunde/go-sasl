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

			return fmt.Errorf("cannot impersonate %s", authz)
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
		{"", "jack", "mcjac", "", "failed"},
	}

	for _, test := range tests {
		client := sasl.NewPlainClientMech(test.authz, test.username, test.password)
		server := sasl.NewPlainServerMech(verifier)

		clientErr, serverErr := runClientServerTest(client, server)
		if test.clientErr != "" {
			if clientErr == nil {
				t.Fatalf("expected a client error, but got none")
			} else if test.clientErr != clientErr.Error() {
				t.Fatalf("expected a client error, but got %v", clientErr)
			}
		}
		if test.serverErr != "" {
			if serverErr == nil {
				t.Fatalf("expected a server error, but got none")
			} else if test.serverErr != serverErr.Error() {
				t.Fatalf("expected a server error, but got %v", clientErr)
			}
		}
	}
}
