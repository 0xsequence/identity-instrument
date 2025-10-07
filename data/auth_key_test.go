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

func TestAuthKey(t *testing.T) {
	// Maximum DynamoDB item size is 400 KB, use 350 KB as a safe margin
	t.Run("maximum possible size is less than 350 KB", func(t *testing.T) {
		id := [32]byte{}
		_, _ = rand.Read(id[:])

		scope := "@1:"
		for i := 0; i < 253; i++ {
			scope += "s"
		}

		// Largest possible proto.Key
		key := proto.Key{
			KeyType: proto.KeyType_WebCrypto_Secp256r1,
			Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3",
		}

		// Assume data contains all fields
		rawData := &proto.AuthKeyData{
			Scope:   proto.Scope(scope),
			AuthKey: key,
			Signer:  key,
			Expiry:  time.Now(),
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
