package kms

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Ciphertext struct {
	EncryptedKey  []byte
	EncryptedData []byte
}

func (c *Ciphertext) Encode() (string, error) {
	if len(c.EncryptedKey) == 0 {
		return "", fmt.Errorf("encrypted key cannot be empty")
	}
	if len(c.EncryptedData) == 0 {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}
	return base64.RawURLEncoding.EncodeToString(c.EncryptedKey) + "." + base64.RawURLEncoding.EncodeToString(c.EncryptedData), nil
}

func DecodeCiphertext(ciphertext string) (*Ciphertext, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}
	encryptedData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}
	if len(encryptedKey) == 0 {
		return nil, fmt.Errorf("encrypted key cannot be empty")
	}
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}
	return &Ciphertext{
		EncryptedKey:  encryptedKey,
		EncryptedData: encryptedData,
	}, nil
}
