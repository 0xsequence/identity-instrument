package proto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
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
	case KeyType_Ethereum_Secp256k1:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return Key{}, fmt.Errorf("invalid private key type: %T", privateKey)
		}
		return Key{
			KeyType: keyType,
			Address: strings.ToLower(crypto.PubkeyToAddress(ecdsaKey.PublicKey).Hex()),
		}, nil

	case KeyType_WebCrypto_Secp256r1:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return Key{}, fmt.Errorf("invalid private key type: %T", privateKey)
		}
		return Key{
			KeyType: keyType,
			Address: ecdsaKey.PublicKey.X.String() + ecdsaKey.PublicKey.Y.String(),
		}, nil
	}

	return Key{}, fmt.Errorf("unsupported key type: %s", keyType)
}

func (k *Key) String() string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s", k.KeyType, strings.ToLower(k.Address))
}

func (k *Key) IsValid() bool {
	if k == nil {
		return false
	}

	b, err := hexutil.Decode(k.Address)
	if err != nil {
		return false
	}

	switch k.KeyType {
	case KeyType_Ethereum_Secp256k1:
		return len(b) == 20
	case KeyType_WebCrypto_Secp256r1:
		return len(b) == 65
	}
	return false
}

func (k *Key) HasValidKeyType() bool {
	return k != nil && k.KeyType.Is(KeyType_Ethereum_Secp256k1, KeyType_WebCrypto_Secp256r1)
}

func (k *Key) Hash() string {
	hash := sha256.Sum256([]byte(k.String()))
	return hex.EncodeToString(hash[:])
}
