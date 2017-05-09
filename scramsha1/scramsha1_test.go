package scramsha1_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/craiggwilson/go-sasl/internal/testhelpers"
	"github.com/craiggwilson/go-sasl/scramsha1"
)

func TestScramSha1Mech(t *testing.T) {

	storedUserProvider := func(_ context.Context, username string) (*scramsha1.StoredUser, error) {
		_, storedKey, serverKey := scramsha1.GenerateKeys("password", []byte("blah"), 100)
		return &scramsha1.StoredUser{
			Salt:       []byte("blah"),
			Iterations: 100,
			StoredKey:  storedKey,
			ServerKey:  serverKey,
		}, nil
	}

	tests := []struct {
		authz     string
		username  string
		password  string
		clientErr string
		serverErr string
	}{
		{"", "jack", "password", "", ""},
		{"jane", "jack", "password", "", ""},
		{"", "jack", "wrong", "sasl mechanism SCRAM-SHA-1: client failed to provide response: other-error", "sasl mechanism SCRAM-SHA-1: server failed to provide challenge: invalid response: client key mismatch"},
	}

	// using math/rand to make the nonce's predicatable. Actual implementation should use crypto/rand.
	mr := rand.New(rand.NewSource(1))

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s:%s:%s", test.authz, test.username, test.password), func(t *testing.T) {
			testhelpers.RunClientServerTest(t,
				scramsha1.NewClientMech(test.authz, test.username, test.password, 16, mr),
				scramsha1.NewServerMech(storedUserProvider, 16, mr),
				test.clientErr,
				test.serverErr,
			)
		})
	}
}
