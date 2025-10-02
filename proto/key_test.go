package proto_test

import (
	"testing"

	"github.com/0xsequence/identity-instrument/proto"
	"github.com/stretchr/testify/require"
)

func TestKey_IsValid(t *testing.T) {
	t.Run("invalid key type", func(t *testing.T) {
		key := proto.Key{KeyType: proto.KeyType("invalid"), Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e"}
		require.False(t, key.IsValid())
	})

	t.Run("Ethereum_Secp256k1", func(t *testing.T) {
		testCases := []struct {
			name  string
			key   proto.Key
			valid bool
		}{
			{
				name:  "valid",
				key:   proto.Key{KeyType: proto.KeyType_Ethereum_Secp256k1, Address: "0x36cf0e1D975f4eF8DbF4C7A70abef0548a68505e"},
				valid: true,
			},
			{
				name:  "empty address",
				key:   proto.Key{KeyType: proto.KeyType_Ethereum_Secp256k1, Address: ""},
				valid: false,
			},
			{
				name:  "not hex",
				key:   proto.Key{KeyType: proto.KeyType_Ethereum_Secp256k1, Address: "invalid"},
				valid: false,
			},
			{
				name:  "full public key as address",
				key:   proto.Key{KeyType: proto.KeyType_Ethereum_Secp256k1, Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3"},
				valid: false,
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.valid, tc.key.IsValid())
			})
		}
	})
	t.Run("WebCrypto_Secp256r1", func(t *testing.T) {
		testCases := []struct {
			name  string
			key   proto.Key
			valid bool
		}{
			{
				name:  "valid",
				key:   proto.Key{KeyType: proto.KeyType_WebCrypto_Secp256r1, Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3"},
				valid: true,
			},
			{
				name:  "empty address",
				key:   proto.Key{KeyType: proto.KeyType_WebCrypto_Secp256r1, Address: ""},
				valid: false,
			},
			{
				name:  "not hex",
				key:   proto.Key{KeyType: proto.KeyType_WebCrypto_Secp256r1, Address: "invalid"},
				valid: false,
			},
			{
				name:  "ethereum address",
				key:   proto.Key{KeyType: proto.KeyType_WebCrypto_Secp256r1, Address: "0x1234567890123456789012345678901234567890"},
				valid: false,
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.valid, tc.key.IsValid())
			})
		}
	})
}
