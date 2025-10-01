package proto_test

import (
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
			Digest: "0x1234567890123456789012345678901234567890123456789012345678901234",
		}
		err := params.Validate()
		require.NoError(t, err)
	})
}
