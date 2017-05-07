package sasl_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"strings"

	"github.com/craiggwilson/go-sasl"
)

func TestAnonMech(t *testing.T) {

	verifier := func(_ context.Context, trace string) error {

		if strings.Contains(trace, "@") {
			return nil
		}

		return errors.New("must provide an email address")
	}

	tests := []struct {
		trace     string
		clientErr string
		serverErr string
	}{
		{"jack@mcjack", "", ""},
		{"jack", "", "sasl mechanism ANONYMOUS: unable to start exchange: must provide an email address"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.trace), func(t *testing.T) {
			client := sasl.NewAnonymousClientMech(test.trace)
			server := sasl.NewAnonymousServerMech(verifier)

			clientErr, serverErr := runClientServerTest(client, server)
			if test.clientErr != "" {
				if clientErr == nil {
					t.Fatalf("expected a client error, but got none")
				} else if test.clientErr != clientErr.Error() {
					t.Fatalf("expected client error to be '%s', but got '%v'", test.clientErr, clientErr.Error())
				}
			}
			if test.serverErr != "" {
				if serverErr == nil {
					t.Fatalf("expected a server error, but got none")
				} else if test.serverErr != serverErr.Error() {
					t.Fatalf("expected server error to be '%s', but got '%v'", test.serverErr, serverErr.Error())
				}
			}
		})
	}
}
