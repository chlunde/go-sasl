package sasl_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"strings"

	"github.com/craiggwilson/go-sasl"
)

func TestAnonymousMech(t *testing.T) {

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
		{"jack", "sasl mechanism ANONYMOUS: failed to receive challenge: context canceled", "sasl mechanism ANONYMOUS: unable to start exchange: must provide an email address"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.trace), func(t *testing.T) {
			runClientServerTest(t, &clientServerTest{
				client:    sasl.NewAnonymousClientMech(test.trace),
				server:    sasl.NewAnonymousServerMech(verifier),
				clientErr: test.clientErr,
				serverErr: test.serverErr,
			})
		})
	}
}
