package data_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/stretchr/testify/require"
)

func TestAuthCommitment(t *testing.T) {
	// Maximum DynamoDB item size is 400 KB, use 350 KB as a safe margin
	t.Run("maximum possible size is less than 350 KB", func(t *testing.T) {
		id := [32]byte{}
		_, _ = rand.Read(id[:])

		var (
			scope    = "@1:"
			s256     string
			metadata = make(map[string]string)
		)
		for i := 0; i < 253; i++ {
			scope += "s"
		}
		for i := 0; i < 256; i++ {
			s256 += "0"
		}
		for i := 0; i < 100; i++ {
			metadata[fmt.Sprintf("key%d", i)] = s256
		}

		// Largest possible proto.Key
		key := proto.Key{
			KeyType: proto.KeyType_WebCrypto_Secp256r1,
			Address: "0x046438a26dc856cf37175f3038be16777d353af67fd8ad9ea5a7f703e5bd830b73e06190850634ba9c97612612089ecb438e7ece3c7b435219c624ff5913cb38d3",
		}

		// Assume data contains all fields
		rawData := &proto.AuthCommitmentData{
			Scope:        proto.Scope(scope),
			AuthKey:      key,
			AuthMode:     proto.AuthMode_AuthCodePKCE,
			IdentityType: proto.IdentityType_Email,
			Handle:       s256, // 256-character string
			Signer:       key,
			Challenge:    s256,     // 256-character string
			Answer:       s256,     // 256-character string
			Metadata:     metadata, // 100 key-value pairs, each 256-character string
			Attempts:     math.MaxUint,
			Expiry:       time.Now(),
		}

		marshalledData, err := json.Marshal(rawData)
		require.NoError(t, err)
		encodedData := base64.StdEncoding.EncodeToString(marshalledData)

		// Assume encrypting the data triples the size
		ciphertext := encodedData + encodedData + encodedData

		commitment := &data.AuthCommitment{
			ID:        hex.EncodeToString(id[:]),
			ExpiresAt: time.Now(),
			AuthID: &proto.AuthID{
				Scope:        proto.Scope(scope),
				AuthMode:     proto.AuthMode_AuthCodePKCE,
				IdentityType: proto.IdentityType_Email,
				Verifier:     s256,
			},
			EncryptedData: data.EncryptedData[*proto.AuthCommitmentData]{
				CipherKeyRef:   hex.EncodeToString(id[:]),
				Ciphertext:     ciphertext,
				CiphertextHash: id[:],
			},
		}

		av, err := attributevalue.Marshal(commitment)
		require.NoError(t, err)
		b, err := json.Marshal(av)
		require.NoError(t, err)
		require.Less(t, len(b), 350*1024)
	})
}
