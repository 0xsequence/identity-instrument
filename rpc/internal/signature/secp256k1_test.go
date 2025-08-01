package signature_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/rpc/internal/signature"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestValidateSecp256k1(t *testing.T) {
	t.Run("InvalidPublicKey", func(t *testing.T) {
		invalidPubKey := "0xdeadbeef"
		digest := []byte("test message")
		sig := make([]byte, 65) // dummy signature

		err := signature.ValidateSecp256k1(invalidPubKey, digest, sig)
		require.Error(t, err)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(t, err)

		address := crypto.PubkeyToAddress(priv.PublicKey).Hex()

		digest := []byte("test message")
		sig := make([]byte, 65)
		copy(sig, []byte("thisisnotavalidsignaturethisisnotavalidsignature123456"))

		err = signature.ValidateSecp256k1(address, digest, sig)
		require.Error(t, err)
	})

	t.Run("ValidSignature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(t, err)

		address := crypto.PubkeyToAddress(priv.PublicKey).Hex()

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
		sig, err := crypto.Sign(prefixedHash, priv)
		require.NoError(t, err)

		err = signature.ValidateSecp256k1(address, digest, sig)
		require.NoError(t, err)
	})
}
