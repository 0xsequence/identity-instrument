package email_test

import (
	"testing"

	"github.com/0xsequence/identity-instrument/rpc/email"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	testCases := []struct {
		name    string
		email   string
		wantErr string
	}{
		{name: "valid", email: "test@example.com", wantErr: ""},
		{name: "without @", email: "testexample.com", wantErr: "incorrect format"},
		{name: "localhost", email: "test@localhost", wantErr: "incorrect format"},
		{name: "too long", email: "test12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890@example.com", wantErr: "too long"},
		{name: "too short", email: "t@t.t", wantErr: "incorrect format"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := email.Validate(tc.email)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
