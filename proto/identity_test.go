package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentity_Validate(t *testing.T) {
	tests := []struct {
		name          string
		identity      Identity
		expectedError bool
		errorContains string
	}{
		// Valid Email identity
		{
			name: "valid email identity",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid email identity with additional fields",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
				Email:   "user@example.com",
				Issuer:  "example.com",
			},
			expectedError: false,
		},

		// Valid OIDC identity
		{
			name: "valid OIDC identity",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
			},
			expectedError: false,
		},
		{
			name: "valid OIDC identity with additional fields",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
				Email:   "user@gmail.com",
			},
			expectedError: false,
		},

		// Invalid Email identity
		{
			name: "invalid email identity - empty subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "",
			},
			expectedError: true,
			errorContains: "email subject cannot be empty",
		},

		// Invalid OIDC identity
		{
			name: "invalid OIDC identity - empty issuer",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "",
				Subject: "123456789",
			},
			expectedError: true,
			errorContains: "OIDC issuer cannot be empty",
		},
		{
			name: "invalid OIDC identity - empty subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "",
			},
			expectedError: true,
			errorContains: "OIDC subject cannot be empty",
		},
		{
			name: "invalid OIDC identity - both issuer and subject empty",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "",
				Subject: "",
			},
			expectedError: true,
			errorContains: "OIDC issuer cannot be empty",
		},

		// Edge cases
		{
			name: "email identity with special characters in subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user+test@example-domain.co.uk",
			},
			expectedError: false,
		},
		{
			name: "email identity with unicode in subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "用户@测试.中国",
			},
			expectedError: false,
		},
		{
			name: "OIDC identity with complex issuer URL",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://login.microsoftonline.com/tenant-id/v2.0",
				Subject: "oid:12345678-1234-1234-1234-123456789012",
			},
			expectedError: false,
		},
		{
			name: "OIDC identity with special characters in subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub:123456789|provider:google",
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.identity.Validate()

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

func TestIdentity_Encode(t *testing.T) {
	tests := []struct {
		name          string
		identity      Identity
		expected      string
		expectedError bool
		errorContains string
	}{
		// Valid Email identity encoding
		{
			name: "valid email identity encoding",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
			},
			expected:      "Email:user@example.com",
			expectedError: false,
		},
		{
			name: "valid email identity with special characters",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user+test@example-domain.co.uk",
			},
			expected:      "Email:user+test@example-domain.co.uk",
			expectedError: false,
		},
		{
			name: "valid email identity with unicode",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "用户@测试.中国",
			},
			expected:      "Email:用户@测试.中国",
			expectedError: false,
		},

		// Valid OIDC identity encoding
		{
			name: "valid OIDC identity encoding",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
			},
			expected:      "OIDC:https://accounts.google.com#123456789",
			expectedError: false,
		},
		{
			name: "valid OIDC identity with complex issuer",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://login.microsoftonline.com/tenant-id/v2.0",
				Subject: "oid:12345678-1234-1234-1234-123456789012",
			},
			expected:      "OIDC:https://login.microsoftonline.com/tenant-id/v2.0#oid:12345678-1234-1234-1234-123456789012",
			expectedError: false,
		},
		{
			name: "valid OIDC identity with special characters in subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub:123456789|provider:google",
			},
			expected:      "OIDC:https://accounts.google.com#sub:123456789|provider:google",
			expectedError: false,
		},

		// Invalid identity encoding
		{
			name: "invalid email identity - empty subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "",
			},
			expectedError: true,
			errorContains: "email subject cannot be empty",
		},
		{
			name: "invalid OIDC identity - empty issuer",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "",
				Subject: "123456789",
			},
			expectedError: true,
			errorContains: "OIDC issuer cannot be empty",
		},
		{
			name: "invalid OIDC identity - empty subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "",
			},
			expectedError: true,
			errorContains: "OIDC subject cannot be empty",
		},
		{
			name: "valid email identity - subject contains colon",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user:test@example.com",
			},
			expected:      "Email:user:test@example.com",
			expectedError: false,
		},
		{
			name: "valid OIDC identity - issuer contains colon",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "accounts.google.com:8080",
				Subject: "123456789",
			},
			expected:      "OIDC:accounts.google.com:8080#123456789",
			expectedError: false,
		},
		{
			name: "valid OIDC identity - subject contains hash",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub#123456789",
			},
			expected:      "OIDC:https://accounts.google.com#sub#123456789",
			expectedError: false,
		},
		{
			name: "invalid OIDC identity - issuer contains fragment",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com#fragment",
				Subject: "123456789",
			},
			expectedError: true,
			errorContains: "OIDC issuer cannot contain fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.identity.Encode()

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

func TestIdentity_FromString(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      Identity
		expectedError bool
		errorContains string
	}{
		// Valid Email identity parsing
		{
			name:  "valid email identity string",
			input: "Email:user@example.com",
			expected: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
			},
			expectedError: false,
		},
		{
			name:  "valid email identity with special characters",
			input: "Email:user+test@example-domain.co.uk",
			expected: Identity{
				Type:    IdentityType_Email,
				Subject: "user+test@example-domain.co.uk",
			},
			expectedError: false,
		},
		{
			name:  "valid email identity with unicode",
			input: "Email:用户@测试.中国",
			expected: Identity{
				Type:    IdentityType_Email,
				Subject: "用户@测试.中国",
			},
			expectedError: false,
		},

		// Valid OIDC identity parsing
		{
			name:  "valid OIDC identity string",
			input: "OIDC:https://accounts.google.com#123456789",
			expected: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
			},
			expectedError: false,
		},
		{
			name:  "valid OIDC identity with complex issuer",
			input: "OIDC:https://login.microsoftonline.com/tenant-id/v2.0#oid:12345678-1234-1234-1234-123456789012",
			expected: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://login.microsoftonline.com/tenant-id/v2.0",
				Subject: "oid:12345678-1234-1234-1234-123456789012",
			},
			expectedError: false,
		},
		{
			name:  "valid OIDC identity with special characters in subject",
			input: "OIDC:https://accounts.google.com#sub:123456789|provider:google",
			expected: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub:123456789|provider:google",
			},
			expectedError: false,
		},

		// Invalid format parsing
		{
			name:          "invalid format - no colon",
			input:         "Emailuser@example.com",
			expectedError: true,
			errorContains: "invalid identity format:",
		},
		{
			name:          "invalid format - empty string",
			input:         "",
			expectedError: true,
			errorContains: "invalid identity format:",
		},
		{
			name:          "invalid format - only type",
			input:         "Email",
			expectedError: true,
			errorContains: "invalid identity format:",
		},
		{
			name:  "valid format - multiple colons in email subject",
			input: "Email:user:example.com",
			expected: Identity{
				Type:    IdentityType_Email,
				Subject: "user:example.com",
			},
			expectedError: false,
		},

		// Invalid OIDC format
		{
			name:          "invalid OIDC format - no hash separator",
			input:         "OIDC:https://accounts.google.com",
			expectedError: true,
			errorContains: "invalid identity format:",
		},
		{
			name:  "valid OIDC format - multiple hash separators in subject",
			input: "OIDC:https://accounts.google.com#subject#extra",
			expected: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "subject#extra",
			},
			expectedError: false,
		},
		{
			name:          "invalid OIDC format - empty issuer",
			input:         "OIDC:#123456789",
			expectedError: true,
			errorContains: "validation failed: OIDC issuer cannot be empty",
		},
		{
			name:          "invalid OIDC format - empty subject",
			input:         "OIDC:https://accounts.google.com#",
			expectedError: true,
			errorContains: "validation failed: OIDC subject cannot be empty",
		},

		// Invalid identity type
		{
			name:          "invalid identity type",
			input:         "InvalidType:user@example.com",
			expectedError: true,
			errorContains: "invalid identity type:",
		},
		{
			name:          "invalid identity type - empty",
			input:         ":user@example.com",
			expectedError: true,
			errorContains: "invalid identity type:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var identity Identity
			err := identity.FromString(tt.input)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, identity)
			}
		})
	}
}

func TestIdentity_Hash(t *testing.T) {
	tests := []struct {
		name          string
		identity      Identity
		expectedError bool
		errorContains string
	}{
		{
			name: "valid email identity hash",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid OIDC identity hash",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
			},
			expectedError: false,
		},
		{
			name: "invalid email identity - should fail hash",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "",
			},
			expectedError: true,
			errorContains: "encode identity:",
		},
		{
			name: "invalid OIDC identity - should fail hash",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "",
				Subject: "123456789",
			},
			expectedError: true,
			errorContains: "encode identity:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := tt.identity.Hash()

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

func TestIdentity_EncodeFromString_Roundtrip(t *testing.T) {
	tests := []struct {
		name       string
		identity   Identity
		shouldFail bool
	}{
		{
			name: "valid email identity roundtrip",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user@example.com",
			},
			shouldFail: false,
		},
		{
			name: "valid email identity with special characters roundtrip",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user+test@example-domain.co.uk",
			},
			shouldFail: false,
		},
		{
			name: "valid email identity with unicode roundtrip",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "用户@测试.中国",
			},
			shouldFail: false,
		},
		{
			name: "valid OIDC identity roundtrip",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "123456789",
			},
			shouldFail: false,
		},
		{
			name: "valid OIDC identity with complex issuer roundtrip",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://login.microsoftonline.com/tenant-id/v2.0",
				Subject: "oid:12345678-1234-1234-1234-123456789012",
			},
			shouldFail: false,
		},
		{
			name: "valid OIDC identity with special characters roundtrip",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub:123456789|provider:google",
			},
			shouldFail: false,
		},
		{
			name: "invalid email identity - empty subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "",
			},
			shouldFail: true,
		},
		{
			name: "invalid OIDC identity - empty issuer",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "",
				Subject: "123456789",
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the original Identity
			encoded, err := tt.identity.Encode()

			if tt.shouldFail {
				require.Error(t, err)
				assert.Empty(t, encoded)
			} else {
				require.NoError(t, err)

				// Parse it back
				var parsed Identity
				err = parsed.FromString(encoded)
				require.NoError(t, err)

				// Should be identical
				assert.Equal(t, tt.identity, parsed)
			}
		})
	}
}

func TestIdentity_Hash_Consistency(t *testing.T) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	// Hash multiple times and ensure consistency
	hash1, err := identity.Hash()
	require.NoError(t, err)
	hash2, err := identity.Hash()
	require.NoError(t, err)
	hash3, err := identity.Hash()
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
	assert.Equal(t, hash2, hash3)
}

func TestIdentity_Hash_Uniqueness(t *testing.T) {
	identity1 := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	identity2 := Identity{
		Type:    IdentityType_Email,
		Subject: "user2@example.com",
	}

	hash1, err := identity1.Hash()
	require.NoError(t, err)
	hash2, err := identity2.Hash()
	require.NoError(t, err)

	// Different Identities should produce different hashes
	assert.NotEqual(t, hash1, hash2)
}

func TestIdentity_Hash_ManualVerification(t *testing.T) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	// Get the hash from the method
	hash, err := identity.Hash()
	require.NoError(t, err)

	// Manually compute the hash
	encoded, err := identity.Encode()
	require.NoError(t, err)
	expectedHash := sha256.Sum256([]byte(encoded))
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	assert.Equal(t, expectedHashStr, hash)
}

func TestIdentity_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		identity      Identity
		expectedError bool
		errorContains string
	}{
		{
			name: "email identity with maximum length subject",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: string(make([]byte, 1000)), // Very long email
			},
			expectedError: false,
		},
		{
			name: "email identity with special characters but valid",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user!@#$%^&*()_+-=[]{}|;':\",.<>?@subdomain.example.com",
			},
			expectedError: false,
		},
		{
			name: "OIDC identity with maximum length issuer and subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://" + string(make([]byte, 500)) + ".com",
				Subject: string(make([]byte, 500)),
			},
			expectedError: false,
		},
		{
			name: "OIDC identity with special characters in both issuer and subject",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://login.example.com/tenant-id/v2.0?param=value&other=test",
				Subject: "oid:12345678-1234-1234-1234-123456789012|provider:azure|tenant:tenant-id",
			},
			expectedError: false,
		},

		// Invalid cases with special characters
		{
			name: "valid email identity - subject contains colon",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user:test@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid email identity - subject contains hash",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user#test@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid email identity - subject contains slash",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user/test@example.com",
			},
			expectedError: false,
		},
		{
			name: "valid OIDC identity - issuer contains colon",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "accounts.google.com:8080",
				Subject: "123456789",
			},
			expectedError: false,
		},
		{
			name: "invalid OIDC identity - issuer contains fragment",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com#fragment",
				Subject: "123456789",
			},
			expectedError: true,
			errorContains: "OIDC issuer cannot contain fragment",
		},
		{
			name: "valid OIDC identity - subject contains colon",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub:123456789",
			},
			expectedError: false,
		},
		{
			name: "valid OIDC identity - subject contains hash",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub#123456789",
			},
			expectedError: false,
		},
		{
			name: "valid OIDC identity - subject contains slash",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub/123456789",
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.identity.Validate()

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

func TestIdentity_AllIdentityTypes(t *testing.T) {
	identityTypes := []IdentityType{
		IdentityType_Email,
		IdentityType_OIDC,
	}

	for _, identityType := range identityTypes {
		t.Run(string(identityType), func(t *testing.T) {
			var identity Identity
			var expectedError bool

			switch identityType {
			case IdentityType_Email:
				identity = Identity{
					Type:    identityType,
					Subject: "user@example.com",
				}
				expectedError = false
			case IdentityType_OIDC:
				identity = Identity{
					Type:    identityType,
					Issuer:  "https://accounts.google.com",
					Subject: "123456789",
				}
				expectedError = false
			}

			err := identity.Validate()
			if expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				encoded, err := identity.Encode()
				require.NoError(t, err)

				var parsed Identity
				err = parsed.FromString(encoded)
				require.NoError(t, err)
				assert.Equal(t, identity, parsed)
			}
		})
	}
}

func TestIdentity_StringEncoding_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		identity Identity
		expected string
	}{
		{
			name: "email identity with colon in subject (should fail validation)",
			identity: Identity{
				Type:    IdentityType_Email,
				Subject: "user:test@example.com",
			},
			expected: "Email:user:test@example.com",
		},
		{
			name: "OIDC identity with hash in subject (should fail validation)",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://example.com",
				Subject: "fragment#123456789",
			},
			expected: "OIDC:https://example.com#fragment#123456789",
		},
		{
			name: "OIDC identity with hash in subject (should fail validation)",
			identity: Identity{
				Type:    IdentityType_OIDC,
				Issuer:  "https://accounts.google.com",
				Subject: "sub#123456789",
			},
			expected: "OIDC:https://accounts.google.com#sub#123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.identity.Encode()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, encoded)

			// Test roundtrip
			var parsed Identity
			err = parsed.FromString(encoded)
			require.NoError(t, err)
			assert.Equal(t, tt.identity, parsed)
		})
	}
}

// Benchmark tests
func BenchmarkIdentity_Validate(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = identity.Validate()
	}
}

func BenchmarkIdentity_Encode(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = identity.Encode()
	}
}

func BenchmarkIdentity_FromString(b *testing.B) {
	identityStr := "Email:user@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var identity Identity
		_ = identity.FromString(identityStr)
	}
}

func BenchmarkIdentity_Hash(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = identity.Hash()
	}
}

func BenchmarkIdentity_EncodeFromString_Roundtrip(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_Email,
		Subject: "user@example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := identity.Encode()
		var parsed Identity
		_ = parsed.FromString(encoded)
	}
}

func BenchmarkIdentity_OIDC_Validate(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_OIDC,
		Issuer:  "https://accounts.google.com",
		Subject: "123456789",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = identity.Validate()
	}
}

func BenchmarkIdentity_OIDC_Encode(b *testing.B) {
	identity := Identity{
		Type:    IdentityType_OIDC,
		Issuer:  "https://accounts.google.com",
		Subject: "123456789",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = identity.Encode()
	}
}

func BenchmarkIdentity_OIDC_FromString(b *testing.B) {
	identityStr := "OIDC:https://accounts.google.com#123456789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var identity Identity
		_ = identity.FromString(identityStr)
	}
}
