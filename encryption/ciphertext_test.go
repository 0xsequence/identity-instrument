package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertext_Encode(t *testing.T) {
	tests := []struct {
		name          string
		version       int
		encryptedData []byte
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name:          "version 1 with simple data",
			version:       1,
			encryptedData: []byte("test-data"),
			expected:      "v1." + base64.RawURLEncoding.EncodeToString([]byte("test-data")),
			expectedError: false,
		},
		{
			name:          "version 1 with binary data",
			version:       1,
			encryptedData: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
			expected:      "v1." + base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}),
			expectedError: false,
		},
		{
			name:          "version 1 with empty data",
			version:       1,
			encryptedData: []byte{},
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "version 1 with large data",
			version:       1,
			encryptedData: make([]byte, 4096),
			expected:      "v1." + base64.RawURLEncoding.EncodeToString(make([]byte, 4096)),
			expectedError: false,
		},
		{
			name:          "version 1 with unicode data",
			version:       1,
			encryptedData: []byte("🔒-encrypted-data-🚀"),
			expected:      "v1." + base64.RawURLEncoding.EncodeToString([]byte("🔒-encrypted-data-🚀")),
			expectedError: false,
		},
		{
			name:          "version 1 with special characters",
			version:       1,
			encryptedData: []byte("data!@#$%^&*()_+-=[]{}|;':\",./<>?"),
			expected:      "v1." + base64.RawURLEncoding.EncodeToString([]byte("data!@#$%^&*()_+-=[]{}|;':\",./<>?")),
			expectedError: false,
		},
		{
			name:          "invalid version 2",
			version:       2,
			encryptedData: []byte("test-data"),
			expectedError: true,
			errorContains: "unsupported version: 2, only version 1 is supported",
		},
		{
			name:          "invalid version 0",
			version:       0,
			encryptedData: []byte("test-data"),
			expectedError: true,
			errorContains: "unsupported version: 0, only version 1 is supported",
		},
		{
			name:          "invalid large version number",
			version:       999,
			encryptedData: []byte("test-data"),
			expectedError: true,
			errorContains: "unsupported version: 999, only version 1 is supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ciphertext{
				Version:       tt.version,
				EncryptedData: tt.encryptedData,
			}
			result, err := c.Encode()

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

func TestDecodeCiphertext(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedVer   int
		expectedData  []byte
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid v1 ciphertext",
			ciphertext:    "v1." + base64.RawURLEncoding.EncodeToString([]byte("test-data")),
			expectedVer:   1,
			expectedData:  []byte("test-data"),
			expectedError: false,
		},
		{
			name:          "invalid v1 with empty data",
			ciphertext:    "v1.",
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "valid v1 with binary data",
			ciphertext:    "v1." + base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03}),
			expectedVer:   1,
			expectedData:  []byte{0x00, 0x01, 0x02, 0x03},
			expectedError: false,
		},
		{
			name:          "invalid - no separator",
			ciphertext:    "v1testdata",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - too many parts",
			ciphertext:    "v1.part1.part2",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - empty string",
			ciphertext:    "",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - unsupported version v0",
			ciphertext:    "v0." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v0",
		},
		{
			name:          "invalid - unsupported version v2",
			ciphertext:    "v2." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v2",
		},
		{
			name:          "invalid - malformed version",
			ciphertext:    "version1." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: version1",
		},
		{
			name:          "invalid - version without v prefix",
			ciphertext:    "1." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: 1",
		},
		{
			name:          "invalid - malformed base64 data",
			ciphertext:    "v1.invalid-base64!",
			expectedError: true,
			errorContains: "decode encrypted data",
		},
		{
			name:          "invalid - only version",
			ciphertext:    "v1",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - only separator",
			ciphertext:    ".",
			expectedError: true,
			errorContains: "unsupported ciphertext version: ",
		},
		{
			name:          "invalid - whitespace around separator",
			ciphertext:    " v1 . data ",
			expectedError: true,
			errorContains: "unsupported ciphertext version:  v1 ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeCiphertext(tt.ciphertext)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedVer, result.Version)
				assert.Equal(t, tt.expectedData, result.EncryptedData)
			}
		})
	}
}

func TestCiphertext_EncodeDecode_Roundtrip(t *testing.T) {
	tests := []struct {
		name          string
		version       int
		encryptedData []byte
		shouldFail    bool
	}{
		{
			name:          "version 1 with simple data",
			version:       1,
			encryptedData: []byte("encrypted-data"),
			shouldFail:    false,
		},
		{
			name:          "version 1 with binary data",
			version:       1,
			encryptedData: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			shouldFail:    false,
		},
		{
			name:          "version 1 with unicode data",
			version:       1,
			encryptedData: []byte("🔒-encrypted-data-🚀"),
			shouldFail:    false,
		},
		{
			name:          "version 1 with large data",
			version:       1,
			encryptedData: make([]byte, 2000),
			shouldFail:    false,
		},
		{
			name:          "version 1 with special characters",
			version:       1,
			encryptedData: []byte("data!@#$%^&*()_+-=[]{}|;':\",./<>?"),
			shouldFail:    false,
		},
		{
			name:          "version 2 (should fail encode)",
			version:       2,
			encryptedData: []byte("test-data"),
			shouldFail:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original ciphertext
			original := &Ciphertext{
				Version:       tt.version,
				EncryptedData: tt.encryptedData,
			}

			// Encode it
			encoded, err := original.Encode()

			if tt.shouldFail {
				require.Error(t, err)
				assert.Empty(t, encoded)
			} else {
				require.NoError(t, err)

				// Decode it back
				decoded, err := DecodeCiphertext(encoded)
				require.NoError(t, err)
				require.NotNil(t, decoded)
				// Note: Version is always set to 1 in DecodeCiphertext regardless of original
				assert.Equal(t, 1, decoded.Version)
				assert.Equal(t, original.EncryptedData, decoded.EncryptedData)
			}
		})
	}
}

func TestCiphertext_Encode_Consistency(t *testing.T) {
	c := &Ciphertext{
		Version:       1,
		EncryptedData: []byte("test-data"),
	}

	// Encode multiple times and ensure consistency
	encoded1, err := c.Encode()
	require.NoError(t, err)
	encoded2, err := c.Encode()
	require.NoError(t, err)
	encoded3, err := c.Encode()
	require.NoError(t, err)

	assert.Equal(t, encoded1, encoded2)
	assert.Equal(t, encoded2, encoded3)
}

func TestDecodeCiphertext_VersionHandling(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedError bool
		errorContains string
	}{
		{
			name:          "supported version v1",
			ciphertext:    "v1." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: false,
		},
		{
			name:          "unsupported version v0",
			ciphertext:    "v0." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v0",
		},
		{
			name:          "unsupported version v2",
			ciphertext:    "v2." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v2",
		},
		{
			name:          "unsupported version v999",
			ciphertext:    "v999." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v999",
		},
		{
			name:          "malformed version - no v prefix",
			ciphertext:    "1." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: 1",
		},
		{
			name:          "malformed version - non-numeric",
			ciphertext:    "vabc." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: vabc",
		},
		{
			name:          "malformed version - empty",
			ciphertext:    "v." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeCiphertext(tt.ciphertext)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, 1, result.Version)
			}
		})
	}
}

func TestCiphertext_Base64Compatibility(t *testing.T) {
	// Test that our encoding is compatible with standard base64.RawURLEncoding
	data := []byte("test-data-123")

	c := &Ciphertext{
		Version:       1,
		EncryptedData: data,
	}

	encoded, err := c.Encode()
	require.NoError(t, err)

	// Manually verify the format
	expectedDataB64 := base64.RawURLEncoding.EncodeToString(data)
	expected := "v1." + expectedDataB64

	assert.Equal(t, expected, encoded)

	// Verify we can decode it back
	decoded, err := DecodeCiphertext(encoded)
	require.NoError(t, err)
	assert.Equal(t, 1, decoded.Version)
	assert.Equal(t, data, decoded.EncryptedData)
}

func TestCiphertext_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedError bool
		errorContains string
	}{
		{
			name:          "very long valid ciphertext",
			ciphertext:    "v1." + base64.RawURLEncoding.EncodeToString(make([]byte, 10000)),
			expectedError: false,
		},
		{
			name:          "version with leading zeros",
			ciphertext:    "v01." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v01",
		},
		{
			name:          "version with negative number",
			ciphertext:    "v-1." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v-1",
		},
		{
			name:          "version with decimal",
			ciphertext:    "v1.5." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "multiple dots in version",
			ciphertext:    "v1.2.3." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeCiphertext(tt.ciphertext)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkCiphertext_Encode(b *testing.B) {
	c := &Ciphertext{
		Version:       1,
		EncryptedData: make([]byte, 4096),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Encode()
	}
}

func BenchmarkDecodeCiphertext(b *testing.B) {
	data := make([]byte, 4096)
	ciphertext := "v1." + base64.RawURLEncoding.EncodeToString(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeCiphertext(ciphertext)
	}
}

func BenchmarkCiphertext_EncodeDecode_Roundtrip(b *testing.B) {
	c := &Ciphertext{
		Version:       1,
		EncryptedData: make([]byte, 4096),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := c.Encode()
		_, _ = DecodeCiphertext(encoded)
	}
}
