package anonymous_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/craiggwilson/go-sasl/anonymous"
	"github.com/craiggwilson/go-sasl/internal/testhelpers"
)

func TestAnonymousMech(t *testing.T) {

	verifier := func(_ context.Context, authz string) error {

		if strings.Contains(authz, "@") {
			return nil
		}

		return errors.New("must provide an email address")
	}

	tests := []struct {
		authz     string
		clientErr string
		serverErr string
	}{
		{"jack@mcjack", "", ""},
		{"jack", "context canceled", "sasl mechanism ANONYMOUS: unable to start exchange: must provide an email address"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.authz), func(t *testing.T) {
			testhelpers.RunClientServerTest(t,
				anonymous.NewClientMech(test.authz),
				anonymous.NewServerMech(verifier),
				test.clientErr,
				test.serverErr,
			)
		})
	}
}
