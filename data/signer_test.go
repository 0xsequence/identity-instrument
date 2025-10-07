package data_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	// Maximum DynamoDB item size is 400 KB, use 350 KB as a safe margin
	t.Run("maximum possible size is less than 350 KB", func(t *testing.T) {
		id := [32]byte{}
		_, _ = rand.Read(id[:])

		var (
			scope = "@1:"
			s256  string
		)
		for i := 0; i < 253; i++ {
			scope += "s"
		}
		for i := 0; i < 256; i++ {
			s256 += "0"
		}

		// Largest possible proto.Key
		key := proto.Key{
			KeyType: proto.KeyType_WebCrypto_Secp256r1,
			Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3",
		}

		// Assume data contains all fields
		rawData := &proto.SignerData{
			Scope: proto.Scope(scope),
			Identity: &proto.Identity{
				Type:    proto.IdentityType_Email,
				Issuer:  s256,
				Subject: s256,
				Email:   s256,
			},
			KeyType:    proto.KeyType_WebCrypto_Secp256r1,
			PrivateKey: key.Address, // larger than expected size
		}

		marshalledData, err := json.Marshal(rawData)
		require.NoError(t, err)
		encodedData := base64.StdEncoding.EncodeToString(marshalledData)

		// Assume encrypting the data triples the size
		ciphertext := encodedData + encodedData + encodedData

		authKey := &data.AuthKey{
			Scope:     proto.Scope(scope),
			Key:       &key,
			ExpiresAt: time.Now(),
			EncryptedData: data.EncryptedData[*proto.AuthKeyData]{
				CipherKeyRef:   hex.EncodeToString(id[:]),
				Ciphertext:     ciphertext,
				CiphertextHash: id[:],
			},
		}

		av, err := attributevalue.Marshal(authKey)
		require.NoError(t, err)
		b, err := json.Marshal(av)
		require.NoError(t, err)
		require.Less(t, len(b), 350*1024)
	})
}
