package external_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/craiggwilson/go-sasl/external"
	"github.com/craiggwilson/go-sasl/internal/testhelpers"
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
		{"jane", "context canceled", "sasl mechanism EXTERNAL: unable to start exchange: invalid credentials"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.authz), func(t *testing.T) {
			testhelpers.RunClientServerTest(t,
				external.NewClientMech(test.authz),
				external.NewServerMech(verifier),
				test.clientErr,
				test.serverErr,
			)
		})
	}
}
