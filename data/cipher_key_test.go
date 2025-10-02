package data_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/data"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/stretchr/testify/require"
)

func TestCipherKey(t *testing.T) {
	// Maximum DynamoDB item size is 400 KB, use 350 KB as a safe margin
	t.Run("maximum possible size is less than 350 KB", func(t *testing.T) {
		// 256-bit hash size
		id := [32]byte{}
		rand.Read(id[:])

		// Attestations are typically no larger than 4 KB. Use 10 KB as a safe margin.
		att := [10 * 1024]byte{}
		rand.Read(att[:])

		var (
			scope           = "@1:"
			s256            string
			s1024           string
			encryptedShares = make(map[string]string)
		)
		for i := 0; i < 253; i++ {
			scope += "s"
		}
		for i := 0; i < 256; i++ {
			s256 += "0"
		}
		for i := 0; i < 1024; i++ {
			s1024 += "0"
		}
		for i := 0; i < 100; i++ {
			ref := "awskms|arn:aws:kms:ca-central-1:000000000000:key/00000000-0000-0000-0000-000000000000" + fmt.Sprintf("%d", i)
			// each share is typically less than 500 characters, use 1024 as a safe margin
			encryptedShares[ref] = s1024
		}

		now := time.Now()
		maxInt := math.MaxInt

		cipherKey := &data.CipherKey{
			Generation:      maxInt,
			KeyIndex:        &maxInt,
			KeyRef:          hex.EncodeToString(id[:]),
			EncryptedShares: encryptedShares,
			Attestation:     att[:],
			CreatedAt:       now,
			InactiveSince:   &now,
		}

		av, err := attributevalue.Marshal(cipherKey)
		require.NoError(t, err)
		b, err := json.Marshal(av)
		require.NoError(t, err)
		require.Less(t, len(b), 350*1024)
	})
}
