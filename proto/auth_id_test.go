package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthID_Validate(t *testing.T) {
	tests := []struct {
		name          string
		authID        AuthID
		expectedError bool
		errorContains string
	}{
		{
			name: "valid auth ID with all fields",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid auth ID with minimal verifier",
			authID: AuthID{
				Scope:        "@456",
				AuthMode:     AuthMode_IDToken,
				IdentityType: IdentityType_OIDC,
				Verifier:     "sub123",
			},
			expectedError: false,
		},
		{
			name: "invalid scope - empty",
			authID: AuthID{
				Scope:        "",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name: "invalid scope - contains slash",
			authID: AuthID{
				Scope:        "@123/test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name: "invalid auth mode - empty",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     "",
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid auth mode:",
		},
		{
			name: "invalid auth mode - contains slash",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     "OTP/Invalid",
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid auth mode:",
		},
		{
			name: "invalid identity type - empty",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: "",
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid identity type:",
		},
		{
			name: "invalid identity type - contains slash",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: "Email/Invalid",
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid identity type:",
		},
		{
			name: "invalid verifier - empty",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "",
			},
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name: "invalid verifier - contains slash",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user/example.com",
			},
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name: "invalid verifier - too long",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     string(make([]byte, 251)), // 251 characters
			},
			expectedError: true,
			errorContains: "verifier is too long: 251",
		},
		{
			name: "valid verifier - exactly 250 characters",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     string(make([]byte, 250)), // 250 characters
			},
			expectedError: false,
		},
		{
			name: "multiple validation errors - all fields invalid",
			authID: AuthID{
				Scope:        "",
				AuthMode:     "",
				IdentityType: "",
				Verifier:     "",
			},
			expectedError: true,
			errorContains: "invalid scope:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.authID.Validate()

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthID_Encode(t *testing.T) {
	tests := []struct {
		name          string
		authID        AuthID
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name: "valid auth ID with all fields",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expected:      "@123:test/OTP/Email/user@example.com",
			expectedError: false,
		},
		{
			name: "valid auth ID with minimal scope",
			authID: AuthID{
				Scope:        "@456",
				AuthMode:     AuthMode_IDToken,
				IdentityType: IdentityType_OIDC,
				Verifier:     "sub123",
			},
			expected:      "@456/IDToken/OIDC/sub123",
			expectedError: false,
		},
		{
			name: "valid auth ID with special characters in verifier",
			authID: AuthID{
				Scope:        "@789:app",
				AuthMode:     AuthMode_AuthCode,
				IdentityType: IdentityType_Email,
				Verifier:     "user+test@example-domain.co.uk",
			},
			expected:      "@789:app/AuthCode/Email/user+test@example-domain.co.uk",
			expectedError: false,
		},
		{
			name: "valid auth ID with unicode in verifier",
			authID: AuthID{
				Scope:        "@999:unicode",
				AuthMode:     AuthMode_AccessToken,
				IdentityType: IdentityType_Email,
				Verifier:     "用户@测试.中国",
			},
			expected:      "@999:unicode/AccessToken/Email/用户@测试.中国",
			expectedError: false,
		},
		{
			name: "invalid auth ID - empty scope",
			authID: AuthID{
				Scope:        "",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name: "invalid auth ID - verifier too long",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     string(make([]byte, 251)),
			},
			expectedError: true,
			errorContains: "verifier is too long: 251",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.authID.Encode()

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAuthID_FromString(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      AuthID
		expectedError bool
		errorContains string
	}{
		{
			name:  "valid auth ID string with all fields",
			input: "@123:test/OTP/Email/user@example.com",
			expected: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: false,
		},
		{
			name:  "valid auth ID string with minimal scope",
			input: "@456/IDToken/OIDC/sub123",
			expected: AuthID{
				Scope:        "@456",
				AuthMode:     AuthMode_IDToken,
				IdentityType: IdentityType_OIDC,
				Verifier:     "sub123",
			},
			expectedError: false,
		},
		{
			name:  "valid auth ID string with special characters",
			input: "@789:app/AuthCode/Email/user+test@example-domain.co.uk",
			expected: AuthID{
				Scope:        "@789:app",
				AuthMode:     AuthMode_AuthCode,
				IdentityType: IdentityType_Email,
				Verifier:     "user+test@example-domain.co.uk",
			},
			expectedError: false,
		},
		{
			name:  "valid auth ID string with unicode",
			input: "@999:unicode/AccessToken/Email/用户@测试.中国",
			expected: AuthID{
				Scope:        "@999:unicode",
				AuthMode:     AuthMode_AccessToken,
				IdentityType: IdentityType_Email,
				Verifier:     "用户@测试.中国",
			},
			expectedError: false,
		},
		{
			name:  "valid auth ID string with AuthCodePKCE",
			input: "@100:pkce/AuthCodePKCE/OIDC/oauth-client-id",
			expected: AuthID{
				Scope:        "@100:pkce",
				AuthMode:     AuthMode_AuthCodePKCE,
				IdentityType: IdentityType_OIDC,
				Verifier:     "oauth-client-id",
			},
			expectedError: false,
		},
		{
			name:          "invalid format - too few parts",
			input:         "@123/OTP/Email",
			expectedError: true,
			errorContains: "invalid auth ID format:",
		},
		{
			name:          "invalid format - too many parts",
			input:         "@123/OTP/Email/user@example.com/extra",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid format - empty string",
			input:         "",
			expectedError: true,
			errorContains: "invalid auth ID format:",
		},
		{
			name:          "invalid format - no separators",
			input:         "invalidauthid",
			expectedError: true,
			errorContains: "invalid auth ID format:",
		},
		{
			name:          "invalid format - only one separator",
			input:         "@123/OTP",
			expectedError: true,
			errorContains: "invalid auth ID format:",
		},
		{
			name:          "invalid format - only two separators",
			input:         "@123/OTP/Email",
			expectedError: true,
			errorContains: "invalid auth ID format:",
		},
		{
			name:          "invalid - empty scope",
			input:         "/OTP/Email/user@example.com",
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid - scope contains slash",
			input:         "@123/test/OTP/Email/user@example.com",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid - empty auth mode",
			input:         "@123:test//Email/user@example.com",
			expectedError: true,
			errorContains: "invalid auth mode:",
		},
		{
			name:          "invalid - auth mode contains slash",
			input:         "@123:test/OTP/Invalid/Email/user@example.com",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid - empty identity type",
			input:         "@123:test/OTP//user@example.com",
			expectedError: true,
			errorContains: "invalid identity type:",
		},
		{
			name:          "invalid - identity type contains slash",
			input:         "@123:test/OTP/Email/Invalid/user@example.com",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid - empty verifier",
			input:         "@123:test/OTP/Email/",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid - verifier contains slash",
			input:         "@123:test/OTP/Email/user/example.com",
			expectedError: true,
			errorContains: "invalid verifier:",
		},
		{
			name:          "invalid - verifier too long",
			input:         "@123:test/OTP/Email/" + string(make([]byte, 251)),
			expectedError: true,
			errorContains: "verifier is too long: 251",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authID, err := parseAuthID(tt.input)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, authID)
			}
		})
	}
}

func TestAuthID_Hash(t *testing.T) {
	tests := []struct {
		name          string
		authID        AuthID
		expectedError bool
		errorContains string
	}{
		{
			name: "valid auth ID hash",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid auth ID hash with different values",
			authID: AuthID{
				Scope:        "@456:app",
				AuthMode:     AuthMode_IDToken,
				IdentityType: IdentityType_OIDC,
				Verifier:     "sub123",
			},
			expectedError: false,
		},
		{
			name: "invalid auth ID - should fail hash",
			authID: AuthID{
				Scope:        "",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: true,
			errorContains: "encode auth ID:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := tt.authID.Hash()

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Empty(t, hash)
			} else {
				require.NoError(t, err)
				// Hash should be a 64-character hex string (SHA256)
				assert.Len(t, hash, 64)
				assert.Regexp(t, "^[a-f0-9]+$", hash)
			}
		})
	}
}

func TestAuthID_EncodeFromString_Roundtrip(t *testing.T) {
	tests := []struct {
		name       string
		authID     AuthID
		shouldFail bool
	}{
		{
			name: "valid roundtrip with all fields",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			shouldFail: false,
		},
		{
			name: "valid roundtrip with minimal scope",
			authID: AuthID{
				Scope:        "@456",
				AuthMode:     AuthMode_IDToken,
				IdentityType: IdentityType_OIDC,
				Verifier:     "sub123",
			},
			shouldFail: false,
		},
		{
			name: "valid roundtrip with special characters",
			authID: AuthID{
				Scope:        "@789:app",
				AuthMode:     AuthMode_AuthCode,
				IdentityType: IdentityType_Email,
				Verifier:     "user+test@example-domain.co.uk",
			},
			shouldFail: false,
		},
		{
			name: "valid roundtrip with unicode",
			authID: AuthID{
				Scope:        "@999:unicode",
				AuthMode:     AuthMode_AccessToken,
				IdentityType: IdentityType_Email,
				Verifier:     "用户@测试.中国",
			},
			shouldFail: false,
		},
		{
			name: "valid roundtrip with AuthCodePKCE",
			authID: AuthID{
				Scope:        "@100:pkce",
				AuthMode:     AuthMode_AuthCodePKCE,
				IdentityType: IdentityType_OIDC,
				Verifier:     "oauth-client-id",
			},
			shouldFail: false,
		},
		{
			name: "invalid roundtrip - empty scope",
			authID: AuthID{
				Scope:        "",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the original AuthID
			encoded, err := tt.authID.Encode()

			if tt.shouldFail {
				require.Error(t, err)
				assert.Empty(t, encoded)
			} else {
				require.NoError(t, err)

				// Parse it back
				parsed, err := parseAuthID(encoded)
				require.NoError(t, err)

				// Should be identical
				assert.Equal(t, tt.authID, parsed)
			}
		})
	}
}

func TestAuthID_Hash_Consistency(t *testing.T) {
	authID := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	// Hash multiple times and ensure consistency
	hash1, err := authID.Hash()
	require.NoError(t, err)
	hash2, err := authID.Hash()
	require.NoError(t, err)
	hash3, err := authID.Hash()
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)
}

func TestAuthID_Hash_Uniqueness(t *testing.T) {
	authID1 := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	authID2 := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user2@example.com",
	}

	hash1, err := authID1.Hash()
	require.NoError(t, err)
	hash2, err := authID2.Hash()
	require.NoError(t, err)

	// Different AuthIDs should produce different hashes
	assert.NotEqual(t, hash1, hash2)
}

func TestAuthID_Hash_ManualVerification(t *testing.T) {
	authID := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	// Get the hash from the method
	hash, err := authID.Hash()
	require.NoError(t, err)

	// Manually compute the hash
	encoded, err := authID.Encode()
	require.NoError(t, err)
	expectedHash := sha256.Sum256([]byte(encoded))
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	assert.Equal(t, expectedHashStr, hash)
}

func TestAuthID_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		authID        AuthID
		expectedError bool
		errorContains string
	}{
		{
			name: "verifier with maximum length",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     string(make([]byte, 250)),
			},
			expectedError: false,
		},
		{
			name: "verifier with special characters but no slashes",
			authID: AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user!@#$%^&*()_+-=[]{}|;':\",.<>?",
			},
			expectedError: false,
		},
		{
			name: "scope with maximum valid length",
			authID: AuthID{
				Scope:        "@999999999:very-long-scope-name-that-is-still-valid",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			},
			expectedError: false,
		},
		{
			name: "all fields with minimum valid values",
			authID: AuthID{
				Scope:        "@1",
				AuthMode:     AuthMode_OTP,
				IdentityType: IdentityType_Email,
				Verifier:     "a",
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.authID.Validate()

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthID_AllAuthModes(t *testing.T) {
	authModes := []AuthMode{
		AuthMode_OTP,
		AuthMode_IDToken,
		AuthMode_AccessToken,
		AuthMode_AuthCode,
		AuthMode_AuthCodePKCE,
	}

	for _, authMode := range authModes {
		t.Run(string(authMode), func(t *testing.T) {
			authID := AuthID{
				Scope:        "@123:test",
				AuthMode:     authMode,
				IdentityType: IdentityType_Email,
				Verifier:     "user@example.com",
			}

			err := authID.Validate()
			require.NoError(t, err)

			encoded, err := authID.Encode()
			require.NoError(t, err)

			parsed, err := parseAuthID(encoded)
			require.NoError(t, err)
			assert.Equal(t, authID, parsed)
		})
	}
}

func TestAuthID_AllIdentityTypes(t *testing.T) {
	identityTypes := []IdentityType{
		IdentityType_Email,
		IdentityType_OIDC,
	}

	for _, identityType := range identityTypes {
		t.Run(string(identityType), func(t *testing.T) {
			authID := AuthID{
				Scope:        "@123:test",
				AuthMode:     AuthMode_OTP,
				IdentityType: identityType,
				Verifier:     "user@example.com",
			}

			err := authID.Validate()
			require.NoError(t, err)

			encoded, err := authID.Encode()
			require.NoError(t, err)

			parsed, err := parseAuthID(encoded)
			require.NoError(t, err)
			assert.Equal(t, authID, parsed)
		})
	}
}

// Benchmark tests
func BenchmarkAuthID_Validate(b *testing.B) {
	authID := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = authID.Validate()
	}
}

func BenchmarkAuthID_Encode(b *testing.B) {
	authID := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = authID.Encode()
	}
}

func BenchmarkAuthID_Hash(b *testing.B) {
	authID := AuthID{
		Scope:        "@123:test",
		AuthMode:     AuthMode_OTP,
		IdentityType: IdentityType_Email,
		Verifier:     "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = authID.Hash()
	}
}

func parseAuthID(s string) (AuthID, error) {
	parts := strings.SplitN(s, "/", 4)
	if len(parts) != 4 {
		return AuthID{}, fmt.Errorf("invalid auth ID format: %s", s)
	}

	authID := AuthID{
		Scope:        Scope(parts[0]),
		AuthMode:     AuthMode(parts[1]),
		IdentityType: IdentityType(parts[2]),
		Verifier:     parts[3],
	}

	return authID, nil
}
