package proto_test

import (
	"fmt"
	"testing"

	"github.com/0xsequence/identity-instrument/proto"
	"github.com/stretchr/testify/require"
)

func TestCommitVerifierParams_Validate(t *testing.T) {
	t.Run("nil params", func(t *testing.T) {
		var params *proto.CommitVerifierParams
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "params is required")
	})

	t.Run("valid params", func(t *testing.T) {
		testCases := []struct {
			name   string
			params proto.CommitVerifierParams
		}{
			{
				name: "minimal valid params",
				params: proto.CommitVerifierParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
				},
			},
			{
				name: "with valid scope",
				params: proto.CommitVerifierParams{
					Scope:        proto.Scope("@123"),
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
				},
			},
			{
				name: "with valid scope and namespace",
				params: proto.CommitVerifierParams{
					Scope:        proto.Scope("@123:namespace"),
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
				},
			},
			{
				name: "with valid signer",
				params: proto.CommitVerifierParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
					Signer: &proto.Key{
						KeyType: proto.KeyType_Ethereum_Secp256k1,
						Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
					},
				},
			},
			{
				name: "OIDC identity type",
				params: proto.CommitVerifierParams{
					IdentityType: proto.IdentityType_OIDC,
					AuthMode:     proto.AuthMode_IDToken,
				},
			},
			{
				name: "all auth modes",
				params: proto.CommitVerifierParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_AccessToken,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.params.Validate()
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		params := proto.CommitVerifierParams{
			Scope:        proto.Scope("invalid-scope"),
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode_OTP,
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid scope")
	})

	t.Run("invalid identity type", func(t *testing.T) {
		params := proto.CommitVerifierParams{
			IdentityType: proto.IdentityType("invalid"),
			AuthMode:     proto.AuthMode_OTP,
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid identity type")
	})

	t.Run("invalid auth mode", func(t *testing.T) {
		params := proto.CommitVerifierParams{
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode("invalid"),
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth mode")
	})

	t.Run("invalid signer", func(t *testing.T) {
		params := proto.CommitVerifierParams{
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode_OTP,
			Signer: &proto.Key{
				KeyType: proto.KeyType("invalid"),
				Address: "invalid",
			},
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signer")
	})

	t.Run("handle length validation", func(t *testing.T) {
		t.Run("valid handle length", func(t *testing.T) {
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Handle:       "valid-handle",
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("handle at max length", func(t *testing.T) {
			longHandle := string(make([]byte, 250))
			for i := range longHandle {
				longHandle = longHandle[:i] + "a" + longHandle[i+1:]
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Handle:       longHandle,
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("handle too long", func(t *testing.T) {
			longHandle := string(make([]byte, 251))
			for i := range longHandle {
				longHandle = longHandle[:i] + "a" + longHandle[i+1:]
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Handle:       longHandle,
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "handle is too long")
		})
	})

	t.Run("metadata length validation", func(t *testing.T) {
		t.Run("valid metadata", func(t *testing.T) {
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Metadata: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("too many metadata entries", func(t *testing.T) {
			metadata := make(map[string]string)
			for i := 0; i < 11; i++ {
				metadata[fmt.Sprintf("key%d", i)] = "value"
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Metadata:     metadata,
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "too many metadata entries")
		})

		t.Run("metadata key too long", func(t *testing.T) {
			longKey := string(make([]byte, 51))
			for i := range longKey {
				longKey = longKey[:i] + "a" + longKey[i+1:]
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Metadata: map[string]string{
					longKey: "value",
				},
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "metadata key is too long")
		})

		t.Run("metadata value too long", func(t *testing.T) {
			longValue := string(make([]byte, 251))
			for i := range longValue {
				longValue = longValue[:i] + "a" + longValue[i+1:]
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Metadata: map[string]string{
					"key": longValue,
				},
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "metadata value for key key is too long")
		})

		t.Run("metadata at max lengths", func(t *testing.T) {
			longKey := string(make([]byte, 50))
			for i := range longKey {
				longKey = longKey[:i] + "a" + longKey[i+1:]
			}
			longValue := string(make([]byte, 250))
			for i := range longValue {
				longValue = longValue[:i] + "a" + longValue[i+1:]
			}
			params := proto.CommitVerifierParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				Metadata: map[string]string{
					longKey: longValue,
				},
			}
			err := params.Validate()
			require.NoError(t, err)
		})
	})
}

func TestCompleteAuthParams_Validate(t *testing.T) {
	t.Run("nil params", func(t *testing.T) {
		var params *proto.CompleteAuthParams
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "params is required")
	})

	t.Run("valid params", func(t *testing.T) {
		testCases := []struct {
			name   string
			params proto.CompleteAuthParams
		}{
			{
				name: "minimal valid params",
				params: proto.CompleteAuthParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
					SignerType:   proto.KeyType_Ethereum_Secp256k1,
				},
			},
			{
				name: "with valid scope",
				params: proto.CompleteAuthParams{
					Scope:        proto.Scope("@123"),
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
					SignerType:   proto.KeyType_Ethereum_Secp256k1,
				},
			},
			{
				name: "with valid scope and namespace",
				params: proto.CompleteAuthParams{
					Scope:        proto.Scope("@123:namespace"),
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
					SignerType:   proto.KeyType_Ethereum_Secp256k1,
				},
			},
			{
				name: "OIDC identity type",
				params: proto.CompleteAuthParams{
					IdentityType: proto.IdentityType_OIDC,
					AuthMode:     proto.AuthMode_IDToken,
					SignerType:   proto.KeyType_WebCrypto_Secp256r1,
				},
			},
			{
				name: "all auth modes",
				params: proto.CompleteAuthParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_AuthCodePKCE,
					SignerType:   proto.KeyType_Ethereum_Secp256k1,
				},
			},
			{
				name: "WebCrypto signer type",
				params: proto.CompleteAuthParams{
					IdentityType: proto.IdentityType_Email,
					AuthMode:     proto.AuthMode_OTP,
					SignerType:   proto.KeyType_WebCrypto_Secp256r1,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.params.Validate()
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		params := proto.CompleteAuthParams{
			Scope:        proto.Scope("invalid-scope"),
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode_OTP,
			SignerType:   proto.KeyType_Ethereum_Secp256k1,
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid scope")
	})

	t.Run("invalid identity type", func(t *testing.T) {
		params := proto.CompleteAuthParams{
			IdentityType: proto.IdentityType("invalid"),
			AuthMode:     proto.AuthMode_OTP,
			SignerType:   proto.KeyType_Ethereum_Secp256k1,
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid identity type")
	})

	t.Run("invalid auth mode", func(t *testing.T) {
		params := proto.CompleteAuthParams{
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode("invalid"),
			SignerType:   proto.KeyType_Ethereum_Secp256k1,
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth mode")
	})

	t.Run("invalid signer type", func(t *testing.T) {
		params := proto.CompleteAuthParams{
			IdentityType: proto.IdentityType_Email,
			AuthMode:     proto.AuthMode_OTP,
			SignerType:   proto.KeyType("invalid"),
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signer type")
	})

	t.Run("verifier length validation", func(t *testing.T) {
		t.Run("valid verifier length", func(t *testing.T) {
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Verifier:     "valid-verifier",
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("verifier at max length", func(t *testing.T) {
			longVerifier := string(make([]byte, 250))
			for i := range longVerifier {
				longVerifier = longVerifier[:i] + "a" + longVerifier[i+1:]
			}
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Verifier:     longVerifier,
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("verifier too long", func(t *testing.T) {
			longVerifier := string(make([]byte, 251))
			for i := range longVerifier {
				longVerifier = longVerifier[:i] + "a" + longVerifier[i+1:]
			}
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Verifier:     longVerifier,
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "verifier is too long")
		})
	})

	t.Run("answer length validation", func(t *testing.T) {
		t.Run("valid answer length", func(t *testing.T) {
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Answer:       "valid-answer",
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("answer at max length", func(t *testing.T) {
			longAnswer := string(make([]byte, 2048))
			for i := range longAnswer {
				longAnswer = longAnswer[:i] + "a" + longAnswer[i+1:]
			}
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Answer:       longAnswer,
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("answer too long", func(t *testing.T) {
			longAnswer := string(make([]byte, 2049))
			for i := range longAnswer {
				longAnswer = longAnswer[:i] + "a" + longAnswer[i+1:]
			}
			params := proto.CompleteAuthParams{
				IdentityType: proto.IdentityType_Email,
				AuthMode:     proto.AuthMode_OTP,
				SignerType:   proto.KeyType_Ethereum_Secp256k1,
				Answer:       longAnswer,
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "answer is too long")
		})
	})
}

func TestSignParams_Validate(t *testing.T) {
	t.Run("nil params", func(t *testing.T) {
		var params *proto.SignParams
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "params is required")
	})

	t.Run("valid params", func(t *testing.T) {
		testCases := []struct {
			name   string
			params proto.SignParams
		}{
			{
				name: "minimal valid params",
				params: proto.SignParams{
					Signer: proto.Key{
						KeyType: proto.KeyType_Ethereum_Secp256k1,
						Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
					},
					Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
					Nonce:  "0x0",
				},
			},
			{
				name: "with valid scope",
				params: proto.SignParams{
					Scope: proto.Scope("@123"),
					Signer: proto.Key{
						KeyType: proto.KeyType_Ethereum_Secp256k1,
						Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
					},
					Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
					Nonce:  "0x0",
				},
			},
			{
				name: "with valid scope and namespace",
				params: proto.SignParams{
					Scope: proto.Scope("@123:namespace"),
					Signer: proto.Key{
						KeyType: proto.KeyType_Ethereum_Secp256k1,
						Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
					},
					Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
					Nonce:  "0x0",
				},
			},
			{
				name: "WebCrypto signer",
				params: proto.SignParams{
					Signer: proto.Key{
						KeyType: proto.KeyType_WebCrypto_Secp256r1,
						Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3",
					},
					Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
					Nonce:  "0x0",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.params.Validate()
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		params := proto.SignParams{
			Scope: proto.Scope("invalid-scope"),
			Signer: proto.Key{
				KeyType: proto.KeyType_Ethereum_Secp256k1,
				Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
			},
			Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
			Nonce:  "0x0",
		}
		err := params.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid scope")
	})

	t.Run("invalid signer", func(t *testing.T) {
		testCases := []struct {
			name   string
			signer proto.Key
		}{
			{
				name: "invalid key type",
				signer: proto.Key{
					KeyType: proto.KeyType("invalid"),
					Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
				},
			},
			{
				name: "invalid address",
				signer: proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: "invalid",
				},
			},
			{
				name: "wrong address length for Ethereum",
				signer: proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: "0x1234567890123456789012345678901234567890123456789012345678901234",
				},
			},
			{
				name: "wrong address length for WebCrypto",
				signer: proto.Key{
					KeyType: proto.KeyType_WebCrypto_Secp256r1,
					Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				params := proto.SignParams{
					Signer: tc.signer,
					Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
					Nonce:  "0x0",
				}
				err := params.Validate()
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid signer")
			})
		}
	})

	t.Run("invalid digest", func(t *testing.T) {
		testCases := []struct {
			name   string
			digest string
		}{
			{
				name:   "empty digest",
				digest: "",
			},
			{
				name:   "invalid hex",
				digest: "invalid",
			},
			{
				name:   "too short",
				digest: "0x1234",
			},
			{
				name:   "too long",
				digest: "0x123456789012345678901234567890123456789012345678901234567890123456",
			},
			{
				name:   "wrong length (not 32 bytes)",
				digest: "0x123456789012345678901234567890123456789012345678901234567890123",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				params := proto.SignParams{
					Signer: proto.Key{
						KeyType: proto.KeyType_Ethereum_Secp256k1,
						Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
					},
					Digest: tc.digest,
					Nonce:  "0x0",
				}
				err := params.Validate()
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid digest")
			})
		}
	})

	t.Run("valid digest format", func(t *testing.T) {
		params := proto.SignParams{
			Signer: proto.Key{
				KeyType: proto.KeyType_Ethereum_Secp256k1,
				Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
			},
			Nonce:  "0x0",
			Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
		}
		err := params.Validate()
		require.NoError(t, err)
	})

	t.Run("nonce length validation", func(t *testing.T) {
		t.Run("valid nonce length", func(t *testing.T) {
			params := proto.SignParams{
				Signer: proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
				},
				Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
				Nonce:  "0x100",
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("nonce at max length", func(t *testing.T) {
			params := proto.SignParams{
				Signer: proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
				},
				Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
				Nonce:  "0xc9f2c9cd04674edea3fffffff",
			}
			err := params.Validate()
			require.NoError(t, err)
		})

		t.Run("nonce too long", func(t *testing.T) {
			longNonce := string(make([]byte, 65))
			for i := range longNonce {
				longNonce = longNonce[:i] + "a" + longNonce[i+1:]
			}
			params := proto.SignParams{
				Signer: proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e",
				},
				Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
				Nonce:  "0x7e37be2022c0914b267fffffff",
			}
			err := params.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), "nonce is too long")
		})
	})
}
