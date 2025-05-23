package proto

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/0xsequence/ethkit/go-ethereum/crypto"
)

func NewKey(keyType KeyType, address string) (Key, error) {
	return Key{
		KeyType: keyType,
		Address: strings.ToLower(address),
	}, nil
}

func NewKeyFromPrivateKey(keyType KeyType, privateKey any) (Key, error) {
	switch keyType {
	case KeyType_Secp256k1:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return Key{}, fmt.Errorf("invalid private key type: %T", privateKey)
		}
		return Key{
			KeyType: keyType,
			Address: strings.ToLower(crypto.PubkeyToAddress(ecdsaKey.PublicKey).Hex()),
		}, nil
	}

	return Key{}, fmt.Errorf("unsupported key type: %s", keyType)
}

func (k *Key) String() string {
	return fmt.Sprintf("%s:%s", k.KeyType, strings.ToLower(k.Address))
}

func (k *Key) IsValid() bool {
	return k != nil && k.HasValidKeyType() && k.Address != ""
}

func (k *Key) HasValidKeyType() bool {
	return k != nil && k.KeyType.Is(KeyType_Secp256k1, KeyType_Secp256r1)
}
