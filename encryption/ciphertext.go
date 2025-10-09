package encryption

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Ciphertext struct {
	Version       int
	EncryptedData []byte
}

func (c *Ciphertext) Encode() (string, error) {
	if c.Version != 1 {
		return "", fmt.Errorf("unsupported version: %d, only version 1 is supported", c.Version)
	}
	if len(c.EncryptedData) == 0 {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}
	return fmt.Sprintf("v%d.%s", c.Version, base64.RawURLEncoding.EncodeToString(c.EncryptedData)), nil
}

func DecodeCiphertext(ciphertext string) (*Ciphertext, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	if parts[0] != "v1" {
		return nil, fmt.Errorf("unsupported ciphertext version: %s", parts[0])
	}
	encryptedData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}
	return &Ciphertext{
		Version:       1,
		EncryptedData: encryptedData,
	}, nil
}
