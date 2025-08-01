package signature

import (
	"errors"
	"fmt"
	"strings"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
)

func ValidateSecp256k1(address string, digest []byte, sigBytes []byte) error {
	// Add Ethereum prefix to the hash
	digestHex := hexutil.Encode(digest)
	prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))

	if len(sigBytes) != 65 {
		return errors.New("invalid signature length")
	}

	// handle recovery byte
	if sigBytes[64] == 27 || sigBytes[64] == 28 {
		sigBytes[64] -= 27
	}

	// Recover the public key from the signature
	pubKey, err := crypto.Ecrecover(prefixedHash, sigBytes)
	if err != nil {
		return fmt.Errorf("failed to recover public key: %w", err)
	}
	addr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

	if !strings.EqualFold(addr.String(), address) {
		return errors.New("verification failed")
	}

	return nil
}
