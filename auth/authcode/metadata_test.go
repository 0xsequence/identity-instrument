package authcode_test

import (
	"testing"

	"github.com/0xsequence/identity-instrument/auth/authcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractMetadata(t *testing.T) {
	cases := []struct {
		name      string
		metadata  map[string]string
		expectErr string
		validate  func(*testing.T, *authcode.Metadata)
	}{
		{
			name: "valid",
			metadata: map[string]string{
				"iss":          "https://example.com",
				"aud":          "audience",
				"redirect_uri": "https://client.com/callback",
			},
			validate: func(t *testing.T, m *authcode.Metadata) {
				assert.Equal(t, m.Issuer, "https://example.com")
				assert.Equal(t, m.Audience, "audience")
				assert.Equal(t, m.RedirectURI, "https://client.com/callback")
			},
		},
		{
			name: "missing iss",
			metadata: map[string]string{
				"aud":          "audience",
				"redirect_uri": "https://client.com/callback",
				"extra":        "extra",
			},
			expectErr: "metadata must contain iss, aud, and redirect_uri",
		},
		{
			name: "missing aud",
			metadata: map[string]string{
				"iss":          "https://example.com",
				"redirect_uri": "https://client.com/callback",
				"extra":        "extra",
			},
			expectErr: "metadata must contain iss, aud, and redirect_uri",
		},
		{
			name: "missing redirect_uri",
			metadata: map[string]string{
				"iss":   "https://example.com",
				"aud":   "audience",
				"extra": "extra",
			},
			expectErr: "metadata must contain iss, aud, and redirect_uri",
		},
		{
			name: "too many params",
			metadata: map[string]string{
				"iss":          "https://example.com",
				"aud":          "audience",
				"redirect_uri": "https://client.com/callback",
				"extra":        "extra",
			},
			expectErr: "metadata must contain iss, aud, and redirect_uri",
		},
		{
			name: "issuer not a URL",
			metadata: map[string]string{
				"iss":          "invalid",
				"aud":          "audience",
				"redirect_uri": "https://client.com/callback",
			},
			expectErr: "issuer must be https",
		},
		{
			name: "invalid issuer scheme",
			metadata: map[string]string{
				"iss":          "http://example.com",
				"aud":          "audience",
				"redirect_uri": "https://client.com/callback",
			},
			expectErr: "issuer must be https",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := authcode.ExtractMetadata(c.metadata)
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
