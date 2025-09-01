package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/0xsequence/ethkit/go-ethereum/common"
)

func ValidateWebCryptoSignature(pubKey string, message []byte, sigBytes []byte) error {
	pubKeyBytes := common.FromHex(pubKey)

	if len(pubKeyBytes) == 0 || pubKeyBytes[0] != 0x04 {
		return errors.New("invalid public key format")
	}

	curveSize := (elliptic.P256().Params().BitSize + 7) >> 3
	expectedLen := 1 + 2*curveSize
	if len(pubKeyBytes) != expectedLen {
		return errors.New("invalid public key length")
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1 : 1+curveSize])
	y := new(big.Int).SetBytes(pubKeyBytes[1+curveSize:])

	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	digestHash := sha256.Sum256(message)
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])
	if !ecdsa.Verify(&pub, digestHash[:], r, s) {
		return errors.New("verification failed")
	}

	return nil
}
