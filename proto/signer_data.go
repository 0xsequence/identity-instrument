package proto

import (
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
)

func (s *SignerData) Address() (string, error) {
	privKey, err := crypto.HexToECDSA(s.PrivateKey[2:])
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(privKey.PublicKey).Hex(), nil
}
