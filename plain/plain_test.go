package plain_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/craiggwilson/go-sasl/internal/testhelpers"
	"github.com/craiggwilson/go-sasl/plain"
)

func TestPlainMech(t *testing.T) {

	userPassVerifier := func(_ context.Context, username, password string) error {
		if username != "jack" && password != "mcjack" {
			return errors.New("invalid username or password")
		}
		return nil
	}

	authzVerifier := func(_ context.Context, username, authz string) error {
		if authz != "" && authz != "jane" {
			return fmt.Errorf("cannot impersonate %s", authz)
		}
		return nil
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
			testhelpers.RunClientServerTest(t,
				plain.NewClientMech(test.authz, test.username, test.password),
				plain.NewServerMech(userPassVerifier, authzVerifier),
				test.clientErr,
				test.serverErr,
			)
		})
	}
}
