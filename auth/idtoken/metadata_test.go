package idtoken_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/auth/idtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractMetadata(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	validExp := strconv.Itoa(int(now.Add(120 * time.Second).Unix()))

	cases := []struct {
		name      string
		metadata  map[string]string
		expectErr string
		validate  func(*testing.T, *idtoken.Metadata)
	}{
		{
			name: "valid",
			metadata: map[string]string{
				"iss": "https://example.com",
				"aud": "audience",
				"exp": validExp,
			},
			validate: func(t *testing.T, m *idtoken.Metadata) {
				assert.Equal(t, m.Issuer, "https://example.com")
				assert.Equal(t, m.Audience, "audience")
				assert.Equal(t, m.ExpiresAt.Unix(), now.Add(120*time.Second).Unix())
			},
		},
		{
			name: "missing iss",
			metadata: map[string]string{
				"aud":   "audience",
				"exp":   validExp,
				"extra": "extra",
			},
			expectErr: "metadata must contain iss, aud, and exp",
		},
		{
			name: "missing aud",
			metadata: map[string]string{
				"iss":   "https://example.com",
				"exp":   validExp,
				"extra": "extra",
			},
			expectErr: "metadata must contain iss, aud, and exp",
		},
		{
			name: "missing exp",
			metadata: map[string]string{
				"iss":   "https://example.com",
				"aud":   "audience",
				"extra": "extra",
			},
			expectErr: "metadata must contain iss, aud, and exp",
		},
		{
			name: "too many params",
			metadata: map[string]string{
				"iss":   "https://example.com",
				"aud":   "audience",
				"exp":   validExp,
				"extra": "extra",
			},
			expectErr: "metadata must contain iss, aud, and exp",
		},
		{
			name: "invalid exp",
			metadata: map[string]string{
				"iss": "https://example.com",
				"aud": "audience",
				"exp": "invalid",
			},
			expectErr: `parse exp: strconv.ParseInt: parsing "invalid": invalid syntax`,
		},
		{
			name: "issuer not a URL",
			metadata: map[string]string{
				"iss": "invalid",
				"aud": "audience",
				"exp": validExp,
			},
			expectErr: "issuer must be https",
		},
		{
			name: "invalid issuer scheme",
			metadata: map[string]string{
				"iss": "http://example.com",
				"aud": "audience",
				"exp": validExp,
			},
			expectErr: "issuer must be https",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := idtoken.ExtractMetadata(c.metadata)
			if c.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.expectErr)
			}
			if c.validate != nil {
				c.validate(t, m)
			}
		})
	}
}
