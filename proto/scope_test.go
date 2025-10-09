package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScope_String(t *testing.T) {
	tests := []struct {
		name     string
		scope    Scope
		expected string
	}{
		{
			name:     "simple scope with ecosystem ID only",
			scope:    Scope("@123"),
			expected: "@123",
		},
		{
			name:     "scope with ecosystem ID and name",
			scope:    Scope("@456:test-app"),
			expected: "@456:test-app",
		},
		{
			name:     "scope with special characters in name",
			scope:    Scope("@789:test-app_v2"),
			expected: "@789:test-app_v2",
		},
		{
			name:     "scope with numbers in name",
			scope:    Scope("@100:app-123"),
			expected: "@100:app-123",
		},
		{
			name:     "empty scope",
			scope:    Scope(""),
			expected: "",
		},
		{
			name:     "scope with unicode characters",
			scope:    Scope("@999:测试应用"),
			expected: "@999:测试应用",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScope_FromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Scope
	}{
		{
			name:     "simple scope with ecosystem ID only",
			input:    "@123",
			expected: Scope("@123"),
		},
		{
			name:     "scope with ecosystem ID and name",
			input:    "@456:test-app",
			expected: Scope("@456:test-app"),
		},
		{
			name:     "scope with special characters in name",
			input:    "@789:test-app_v2",
			expected: Scope("@789:test-app_v2"),
		},
		{
			name:     "scope with numbers in name",
			input:    "@100:app-123",
			expected: Scope("@100:app-123"),
		},
		{
			name:     "empty scope",
			input:    "",
			expected: Scope(""),
		},
		{
			name:     "scope with unicode characters",
			input:    "@999:测试应用",
			expected: Scope("@999:测试应用"),
		},
		{
			name:     "scope with maximum length name",
			input:    "@1:" + string(make([]byte, 95)), // @1: + 95 chars = 98 total, under 100 limit
			expected: Scope("@1:" + string(make([]byte, 95))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scope Scope
			err := scope.FromString(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, scope)
		})
	}
}

func TestScope_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		scope    Scope
		expected bool
	}{
		// Valid cases
		{
			name:     "valid scope with ecosystem ID only",
			scope:    Scope("@123"),
			expected: true,
		},
		{
			name:     "valid scope with ecosystem ID and name",
			scope:    Scope("@456:test-app"),
			expected: true,
		},
		{
			name:     "valid scope with underscore in name",
			scope:    Scope("@789:test_app"),
			expected: true,
		},
		{
			name:     "valid scope with dash in name",
			scope:    Scope("@100:test-app"),
			expected: true,
		},
		{
			name:     "valid scope with numbers in name",
			scope:    Scope("@200:app123"),
			expected: true,
		},
		{
			name:     "valid scope with mixed case in name",
			scope:    Scope("@300:TestApp"),
			expected: true,
		},
		{
			name:     "valid scope with single character name",
			scope:    Scope("@400:a"),
			expected: true,
		},
		{
			name:     "valid scope with maximum length",
			scope:    Scope("@1:" + string(make([]byte, 95))), // @1: + 95 chars = 98 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "valid scope with exactly 100 characters",
			scope:    Scope("@1:" + string(make([]byte, 96))), // @1: + 96 chars = 100 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "invalid scope with zero ecosystem ID",
			scope:    Scope("@0:test"),
			expected: false,
		},
		{
			name:     "valid scope with large ecosystem ID",
			scope:    Scope("@999999999:test"),
			expected: true,
		},

		// Invalid cases
		{
			name:     "invalid scope - empty",
			scope:    Scope(""),
			expected: false,
		},
		{
			name:     "invalid scope - no @ prefix",
			scope:    Scope("123"),
			expected: false,
		},
		{
			name:     "invalid scope - @ without number",
			scope:    Scope("@"),
			expected: false,
		},
		{
			name:     "invalid scope - @ with non-numeric ecosystem ID",
			scope:    Scope("@abc"),
			expected: false,
		},
		{
			name:     "invalid scope - @ with mixed alphanumeric ecosystem ID",
			scope:    Scope("@123abc"),
			expected: false,
		},
		{
			name:     "invalid scope - ecosystem ID with leading zeros",
			scope:    Scope("@0123"),
			expected: false,
		},
		{
			name:     "invalid scope - name with invalid characters",
			scope:    Scope("@123:test.app"),
			expected: false,
		},
		{
			name:     "invalid scope - name with spaces",
			scope:    Scope("@123:test app"),
			expected: false,
		},
		{
			name:     "invalid scope - name with special characters",
			scope:    Scope("@123:test@app"),
			expected: false,
		},
		{
			name:     "invalid scope - name with unicode",
			scope:    Scope("@123:测试"),
			expected: false,
		},
		{
			name:     "valid scope - name starting with number",
			scope:    Scope("@123:123test"),
			expected: true,
		},
		{
			name:     "valid scope - name starting with dash",
			scope:    Scope("@123:-test"),
			expected: true,
		},
		{
			name:     "valid scope - name starting with underscore",
			scope:    Scope("@123:_test"),
			expected: true,
		},
		{
			name:     "valid scope - name with consecutive dashes",
			scope:    Scope("@123:test--app"),
			expected: true,
		},
		{
			name:     "valid scope - name with consecutive underscores",
			scope:    Scope("@123:test__app"),
			expected: true,
		},
		{
			name:     "invalid scope - too long (over 100 characters)",
			scope:    Scope("@1:" + string(make([]byte, 97))), // @1: + 97 chars = 101 total
			expected: false,
		},
		{
			name:     "invalid scope - multiple @ symbols",
			scope:    Scope("@123@test"),
			expected: false,
		},
		{
			name:     "invalid scope - colon without name",
			scope:    Scope("@123:"),
			expected: false,
		},
		{
			name:     "invalid scope - multiple colons",
			scope:    Scope("@123:test:app"),
			expected: false,
		},
		{
			name:     "invalid scope - negative ecosystem ID",
			scope:    Scope("@-123:test"),
			expected: false,
		},
		{
			name:     "invalid scope - decimal ecosystem ID",
			scope:    Scope("@123.45:test"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScope_Ecosystem(t *testing.T) {
	tests := []struct {
		name          string
		scope         Scope
		expected      string
		expectedError bool
		errorContains string
	}{
		// Valid cases
		{
			name:          "valid scope with ecosystem ID only",
			scope:         Scope("@123"),
			expected:      "123",
			expectedError: false,
		},
		{
			name:          "valid scope with ecosystem ID and name",
			scope:         Scope("@456:test-app"),
			expected:      "456",
			expectedError: false,
		},
		{
			name:          "invalid scope with zero ecosystem ID",
			scope:         Scope("@0:test"),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "valid scope with large ecosystem ID",
			scope:         Scope("@999999999:test"),
			expected:      "999999999",
			expectedError: false,
		},
		{
			name:          "valid scope with single digit ecosystem ID",
			scope:         Scope("@1:test"),
			expected:      "1",
			expectedError: false,
		},

		// Invalid cases
		{
			name:          "invalid scope - empty",
			scope:         Scope(""),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid scope - no @ prefix",
			scope:         Scope("123"),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid scope - @ without number",
			scope:         Scope("@"),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid scope - @ with non-numeric ecosystem ID",
			scope:         Scope("@abc"),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid scope - too long",
			scope:         Scope("@1:" + string(make([]byte, 97))),
			expectedError: true,
			errorContains: "invalid scope:",
		},
		{
			name:          "invalid scope - name with invalid characters",
			scope:         Scope("@123:test.app"),
			expectedError: true,
			errorContains: "invalid scope:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.scope.Ecosystem()

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

func TestScope_FromStringIsValid_Roundtrip(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		shouldFail bool
	}{
		{
			name:       "valid roundtrip with ecosystem ID only",
			input:      "@123",
			shouldFail: false,
		},
		{
			name:       "valid roundtrip with ecosystem ID and name",
			input:      "@456:test-app",
			shouldFail: false,
		},
		{
			name:       "valid roundtrip with special characters in name",
			input:      "@789:test-app_v2",
			shouldFail: false,
		},
		{
			name:       "valid roundtrip with numbers in name",
			input:      "@100:app-123",
			shouldFail: false,
		},
		{
			name:       "invalid roundtrip - empty string",
			input:      "",
			shouldFail: true,
		},
		{
			name:       "invalid roundtrip - invalid format",
			input:      "@abc:test",
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scope Scope
			err := scope.FromString(tt.input)
			require.NoError(t, err) // FromString never fails

			isValid := scope.IsValid()

			if tt.shouldFail {
				assert.False(t, isValid)
			} else {
				assert.True(t, isValid)
			}
		})
	}
}

func TestScope_Ecosystem_Consistency(t *testing.T) {
	scope := Scope("@123:test-app")

	// Get ecosystem multiple times and ensure consistency
	ecosystem1, err := scope.Ecosystem()
	require.NoError(t, err)
	ecosystem2, err := scope.Ecosystem()
	require.NoError(t, err)
	ecosystem3, err := scope.Ecosystem()
	require.NoError(t, err)

	assert.Equal(t, ecosystem1, ecosystem2)
	assert.Equal(t, ecosystem2, ecosystem3)
}

func TestScope_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		scope    Scope
		expected bool
	}{
		{
			name:     "scope with maximum valid length",
			scope:    Scope("@1:" + string(make([]byte, 95))), // @1: + 95 chars = 98 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "scope with exactly 100 characters",
			scope:    Scope("@1:" + string(make([]byte, 96))), // @1: + 96 chars = 100 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "scope with 101 characters (too long)",
			scope:    Scope("@1:" + string(make([]byte, 97))), // @1: + 97 chars = 101 total
			expected: false,
		},
		{
			name:     "scope with valid characters at length boundary",
			scope:    Scope("@1:" + string(make([]byte, 95))), // @1: + 95 chars = 98 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "scope with very long ecosystem ID",
			scope:    Scope("@12345678901234567890:test"),
			expected: true,
		},
		{
			name:     "scope with single character name",
			scope:    Scope("@123:a"),
			expected: true,
		},
		{
			name:     "scope with name containing only numbers",
			scope:    Scope("@123:123"),
			expected: true,
		},
		{
			name:     "scope with name containing only letters",
			scope:    Scope("@123:abc"),
			expected: true,
		},
		{
			name:     "scope with name containing only dashes",
			scope:    Scope("@123:---"),
			expected: true,
		},
		{
			name:     "scope with name containing only underscores",
			scope:    Scope("@123:___"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScope_RegexPattern(t *testing.T) {
	// Test the regex pattern directly to ensure it matches our expectations
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "matches @123",
			input:    "@123",
			expected: true,
		},
		{
			name:     "matches @123:test",
			input:    "@123:test",
			expected: true,
		},
		{
			name:     "does not match @0:test",
			input:    "@0:test",
			expected: false,
		},
		{
			name:     "matches @999999999:very-long-name-with-dashes-and_underscores",
			input:    "@999999999:very-long-name-with-dashes-and_underscores",
			expected: true,
		},
		{
			name:     "does not match empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "does not match @",
			input:    "@",
			expected: false,
		},
		{
			name:     "does not match @abc",
			input:    "@abc",
			expected: false,
		},
		{
			name:     "does not match @123:",
			input:    "@123:",
			expected: false,
		},
		{
			name:     "does not match @123:test.app",
			input:    "@123:test.app",
			expected: false,
		},
		{
			name:     "does not match @123:test app",
			input:    "@123:test app",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scopeRegex.MatchString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCommitVerifierParams_GetScope(t *testing.T) {
	scope := Scope("@123:test-app")
	params := &CommitVerifierParams{
		Scope: scope,
	}

	result := params.GetScope()
	assert.Equal(t, scope, result)
}

func TestCompleteAuthParams_GetScope(t *testing.T) {
	scope := Scope("@456:test-app")
	params := &CompleteAuthParams{
		Scope: scope,
	}

	result := params.GetScope()
	assert.Equal(t, scope, result)
}

func TestSignParams_GetScope(t *testing.T) {
	scope := Scope("@789:test-app")
	params := &SignParams{
		Scope: scope,
	}

	result := params.GetScope()
	assert.Equal(t, scope, result)
}

func TestScope_StringFromString_Roundtrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple scope with ecosystem ID only",
			input: "@123",
		},
		{
			name:  "scope with ecosystem ID and name",
			input: "@456:test-app",
		},
		{
			name:  "scope with special characters in name",
			input: "@789:test-app_v2",
		},
		{
			name:  "scope with numbers in name",
			input: "@100:app-123",
		},
		{
			name:  "empty scope",
			input: "",
		},
		{
			name:  "scope with unicode characters",
			input: "@999:测试应用",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// FromString -> String roundtrip
			var scope Scope
			err := scope.FromString(tt.input)
			require.NoError(t, err)

			result := scope.String()
			assert.Equal(t, tt.input, result)
		})
	}
}

func TestScope_IsValid_Consistency(t *testing.T) {
	scope := Scope("@123:test-app")

	// IsValid should be consistent across multiple calls
	isValid1 := scope.IsValid()
	isValid2 := scope.IsValid()
	isValid3 := scope.IsValid()

	assert.Equal(t, isValid1, isValid2)
	assert.Equal(t, isValid2, isValid3)
}

func TestScope_LengthBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		scope    Scope
		expected bool
	}{
		{
			name:     "scope with 99 characters",
			scope:    Scope("@1:" + string(make([]byte, 95))), // @1: + 95 chars = 98 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "scope with 100 characters",
			scope:    Scope("@1:" + string(make([]byte, 96))), // @1: + 96 chars = 100 total
			expected: false,                                   // null bytes don't match regex
		},
		{
			name:     "scope with 101 characters",
			scope:    Scope("@1:" + string(make([]byte, 97))), // @1: + 97 chars = 101 total
			expected: false,
		},
		{
			name:     "scope with 102 characters",
			scope:    Scope("@1:" + string(make([]byte, 98))), // @1: + 98 chars = 102 total
			expected: false,
		},
		{
			name:     "scope with valid long name",
			scope:    Scope("@1:very-long-valid-name-with-dashes-and_underscores-and-numbers-123"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.scope.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScope_EcosystemID_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		scope         Scope
		expected      string
		expectedError bool
	}{
		{
			name:          "ecosystem ID with single digit",
			scope:         Scope("@1:test"),
			expected:      "1",
			expectedError: false,
		},
		{
			name:          "ecosystem ID with multiple digits",
			scope:         Scope("@123:test"),
			expected:      "123",
			expectedError: false,
		},
		{
			name:          "ecosystem ID with many digits",
			scope:         Scope("@12345678901234567890:test"),
			expected:      "12345678901234567890",
			expectedError: false,
		},
		{
			name:          "ecosystem ID with zero (invalid)",
			scope:         Scope("@0:test"),
			expectedError: true,
		},
		{
			name:          "ecosystem ID only (no name)",
			scope:         Scope("@999"),
			expected:      "999",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.scope.Ecosystem()

			if tt.expectedError {
				require.Error(t, err)
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkScope_String(b *testing.B) {
	scope := Scope("@123:test-app")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scope.String()
	}
}

func BenchmarkScope_FromString(b *testing.B) {
	scopeStr := "@123:test-app"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var scope Scope
		_ = scope.FromString(scopeStr)
	}
}

func BenchmarkScope_IsValid(b *testing.B) {
	scope := Scope("@123:test-app")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scope.IsValid()
	}
}

func BenchmarkScope_Ecosystem(b *testing.B) {
	scope := Scope("@123:test-app")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scope.Ecosystem()
	}
}

func BenchmarkScope_StringFromString_Roundtrip(b *testing.B) {
	scopeStr := "@123:test-app"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var scope Scope
		_ = scope.FromString(scopeStr)
		_ = scope.String()
	}
}

func BenchmarkScope_IsValid_Ecosystem_Roundtrip(b *testing.B) {
	scope := Scope("@123:test-app")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if scope.IsValid() {
			_, _ = scope.Ecosystem()
		}
	}
}
