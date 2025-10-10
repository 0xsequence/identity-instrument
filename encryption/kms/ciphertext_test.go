package kms

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertext_Encode(t *testing.T) {
	tests := []struct {
		name          string
		encryptedKey  []byte
		encryptedData []byte
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name:          "empty key",
			encryptedKey:  []byte{},
			encryptedData: []byte("data"),
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "empty data",
			encryptedKey:  []byte("key"),
			encryptedData: []byte{},
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "both empty",
			encryptedKey:  []byte{},
			encryptedData: []byte{},
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "simple data",
			encryptedKey:  []byte("key"),
			encryptedData: []byte("data"),
			expected:      base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: false,
		},
		{
			name:          "binary data",
			encryptedKey:  []byte{0x00, 0x01, 0x02, 0x03},
			encryptedData: []byte{0xFF, 0xFE, 0xFD, 0xFC},
			expected:      base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03}) + "." + base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0xFE, 0xFD, 0xFC}),
			expectedError: false,
		},
		{
			name:          "large data",
			encryptedKey:  make([]byte, 1024),
			encryptedData: make([]byte, 2048),
			expected:      base64.RawURLEncoding.EncodeToString(make([]byte, 1024)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 2048)),
			expectedError: false,
		},
		{
			name:          "special characters",
			encryptedKey:  []byte("key-with-special-chars!@#$%"),
			encryptedData: []byte("data-with-unicode-🚀"),
			expected:      base64.RawURLEncoding.EncodeToString([]byte("key-with-special-chars!@#$%")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data-with-unicode-🚀")),
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ciphertext{
				EncryptedKey:  tt.encryptedKey,
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
		expectedKey   []byte
		expectedData  []byte
		expectedError bool
		errorContains string
	}{
		{
			name:          "valid simple ciphertext",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedKey:   []byte("key"),
			expectedData:  []byte("data"),
			expectedError: false,
		},
		{
			name:          "invalid - empty data",
			ciphertext:    ".",
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "valid binary data",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02}) + "." + base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0xFE, 0xFD}),
			expectedKey:   []byte{0x00, 0x01, 0x02},
			expectedData:  []byte{0xFF, 0xFE, 0xFD},
			expectedError: false,
		},
		{
			name:          "invalid - no separator",
			ciphertext:    "invalidciphertext",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - too many parts",
			ciphertext:    "part1.part2.part3",
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
			name:          "invalid - empty key and data",
			ciphertext:    ".",
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "invalid - malformed base64 key",
			ciphertext:    "invalid-base64!.validbase64data",
			expectedError: true,
			errorContains: "decode encrypted key",
		},
		{
			name:          "invalid - malformed base64 data",
			ciphertext:    "validbase64key.invalid-base64!",
			expectedError: true,
			errorContains: "decode encrypted data",
		},
		{
			name:          "invalid - both parts malformed",
			ciphertext:    "invalid-base64!.invalid-base64!",
			expectedError: true,
			errorContains: "decode encrypted key",
		},
		{
			name:          "invalid - empty key",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte{}) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "invalid - empty data",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte{}),
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "valid with padding characters",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedKey:   []byte("key"),
			expectedData:  []byte("data"),
			expectedError: false,
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
				assert.Equal(t, tt.expectedKey, result.EncryptedKey)
				assert.Equal(t, tt.expectedData, result.EncryptedData)
			}
		})
	}
}

func TestCiphertext_EncodeDecode_Roundtrip(t *testing.T) {
	tests := []struct {
		name          string
		encryptedKey  []byte
		encryptedData []byte
	}{
		{
			name:          "simple text",
			encryptedKey:  []byte("encryption-key"),
			encryptedData: []byte("sensitive-data"),
		},
		{
			name:          "binary data",
			encryptedKey:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			encryptedData: []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA},
		},
		{
			name:          "unicode data",
			encryptedKey:  []byte("🔑-encryption-key"),
			encryptedData: []byte("🔒-sensitive-data-🚀"),
		},
		{
			name:          "large data",
			encryptedKey:  make([]byte, 1000),
			encryptedData: make([]byte, 2000),
		},
		{
			name:          "special characters",
			encryptedKey:  []byte("key!@#$%^&*()_+-=[]{}|;':\",./<>?"),
			encryptedData: []byte("data!@#$%^&*()_+-=[]{}|;':\",./<>?"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original ciphertext
			original := &Ciphertext{
				EncryptedKey:  tt.encryptedKey,
				EncryptedData: tt.encryptedData,
			}

			// Encode it
			encoded, err := original.Encode()
			require.NoError(t, err)

			// Decode it back
			decoded, err := DecodeCiphertext(encoded)
			require.NoError(t, err)

			// Verify roundtrip
			assert.Equal(t, original.EncryptedKey, decoded.EncryptedKey)
			assert.Equal(t, original.EncryptedData, decoded.EncryptedData)
		})
	}
}

func TestCiphertext_Encode_Consistency(t *testing.T) {
	c := &Ciphertext{
		EncryptedKey:  []byte("test-key"),
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

func TestDecodeCiphertext_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedError bool
		errorContains string
	}{
		{
			name:          "whitespace around separator",
			ciphertext:    " key . data ",
			expectedError: true,
			errorContains: "decode encrypted key",
		},
		{
			name:          "multiple separators",
			ciphertext:    "key.data.extra",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "separator at start",
			ciphertext:    ".data",
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "separator at end",
			ciphertext:    "key.",
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "very long valid ciphertext",
			ciphertext:    base64.RawURLEncoding.EncodeToString(make([]byte, 10000)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 10000)),
			expectedError: false,
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

func TestCiphertext_Base64Compatibility(t *testing.T) {
	// Test that our encoding is compatible with standard base64.RawURLEncoding
	key := []byte("test-key-123")
	data := []byte("test-data-456")

	c := &Ciphertext{
		EncryptedKey:  key,
		EncryptedData: data,
	}

	encoded, err := c.Encode()
	require.NoError(t, err)

	// Manually verify the base64 encoding
	expectedKeyB64 := base64.RawURLEncoding.EncodeToString(key)
	expectedDataB64 := base64.RawURLEncoding.EncodeToString(data)
	expected := expectedKeyB64 + "." + expectedDataB64

	assert.Equal(t, expected, encoded)

	// Verify we can decode it back
	decoded, err := DecodeCiphertext(encoded)
	require.NoError(t, err)
	assert.Equal(t, key, decoded.EncryptedKey)
	assert.Equal(t, data, decoded.EncryptedData)
}

// Benchmark tests
func BenchmarkCiphertext_Encode(b *testing.B) {
	c := &Ciphertext{
		EncryptedKey:  make([]byte, 1024),
		EncryptedData: make([]byte, 4096),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Encode()
	}
}

func BenchmarkDecodeCiphertext(b *testing.B) {
	key := make([]byte, 1024)
	data := make([]byte, 4096)
	ciphertext := base64.RawURLEncoding.EncodeToString(key) + "." + base64.RawURLEncoding.EncodeToString(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeCiphertext(ciphertext)
	}
}

func BenchmarkCiphertext_EncodeDecode_Roundtrip(b *testing.B) {
	c := &Ciphertext{
		EncryptedKey:  make([]byte, 1024),
		EncryptedData: make([]byte, 4096),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, _ := c.Encode()
		_, _ = DecodeCiphertext(encoded)
	}
}
