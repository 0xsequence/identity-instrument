package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/0xsequence/identity-instrument/attestation"
	"github.com/0xsequence/nitrocontrol/aescbc"
)

type KMSKey struct {
	keyARN string
}

func NewKMSKey(keyARN string) *KMSKey {
	return &KMSKey{
		keyARN: keyARN,
	}
}

func (k *KMSKey) CryptorID() string {
	return "awskms|" + k.keyARN
}

func (k *KMSKey) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	att := attestation.FromContext(ctx)

	dataKey, err := att.GenerateDataKey(ctx, k.keyARN)
	if err != nil {
		return "", fmt.Errorf("generate data key: %w", err)
	}

	encrypted, err := aescbc.Encrypt(att, dataKey.Plaintext, plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	ciphertextParts := []string{
		base64.RawURLEncoding.EncodeToString(dataKey.Ciphertext),
		base64.RawURLEncoding.EncodeToString(encrypted),
	}
	return strings.Join(ciphertextParts, "."), nil
}

func (k *KMSKey) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	dataKeyCiphertext, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode data key ciphertext: %w", err)
	}

	encrypted, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}

	att := attestation.FromContext(ctx)
	dataKey, err := att.Decrypt(ctx, dataKeyCiphertext, []string{k.keyARN})
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}

	plaintext, err := aescbc.Decrypt(dataKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
