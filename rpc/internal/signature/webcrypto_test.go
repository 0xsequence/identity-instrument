package signature_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/0xsequence/identity-instrument/rpc/internal/signature"
	"github.com/stretchr/testify/require"
)

func TestValidateWebCryptoSignature(t *testing.T) {
	t.Run("InvalidPublicKey", func(t *testing.T) {
		invalidPubKey := "0xdeadbeef"
		message := []byte("test message")
		sig := make([]byte, 64) // dummy signature

		err := signature.ValidateWebCryptoSignature(invalidPubKey, message, sig)
		require.Error(t, err)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		// Generate a valid key pair
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKeyHex := marshalPublicKey(&priv.PublicKey)

		message := []byte("test message")
		// Create a random (invalid) signature
		sig := make([]byte, 64)
		copy(sig, []byte("thisisnotavalidsignaturethisisnotavalidsignature123456"))

		err = signature.ValidateWebCryptoSignature(pubKeyHex, message, sig)
		require.Error(t, err)
	})

	t.Run("ValidSignature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKeyHex := marshalPublicKey(&priv.PublicKey)

		message := []byte("test message")
		hash := sha256.Sum256(message)
		r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
		require.NoError(t, err)

		sig := make([]byte, 64)
		copy(sig[0:32], r.Bytes())
		copy(sig[32:64], s.Bytes())

		err = signature.ValidateWebCryptoSignature(pubKeyHex, message, sig)
		require.NoError(t, err)
	})
}

func marshalPublicKey(pub *ecdsa.PublicKey) string {
	curveSize := (pub.Curve.Params().BitSize + 7) >> 3
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	paddedX := append(make([]byte, curveSize-len(xBytes)), xBytes...)
	paddedY := append(make([]byte, curveSize-len(yBytes)), yBytes...)
	pubBytes := append([]byte{0x04}, append(paddedX, paddedY...)...)
	return "0x" + hex.EncodeToString(pubBytes)
}
