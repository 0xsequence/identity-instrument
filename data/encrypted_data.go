package data

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xsequence/nitrocontrol/enclave"
)

type Encryptor interface {
	Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (keyID string, ciphertext string, err error)
}

type Decryptor interface {
	Decrypt(ctx context.Context, att *enclave.Attestation, keyID string, ciphertext string) ([]byte, error)
}

type EncryptedData[T any] struct {
	CipherKeyRef string `dynamodbav:"CipherKeyRef"`
	Ciphertext   string `dynamodbav:"Ciphertext"`
}

func Encrypt[T any](ctx context.Context, att *enclave.Attestation, encryptor Encryptor, data T) (EncryptedData[T], error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return EncryptedData[T]{}, fmt.Errorf("marshal data: %w", err)
	}

	keyID, ciphertext, err := encryptor.Encrypt(ctx, att, plaintext)
	if err != nil {
		return EncryptedData[T]{}, err
	}

	ed := EncryptedData[T]{
		CipherKeyRef: keyID,
		Ciphertext:   ciphertext,
	}
	return ed, nil
}

func (ed *EncryptedData[T]) Decrypt(ctx context.Context, att *enclave.Attestation, decryptor Decryptor) (T, error) {
	var zero T

	plaintext, err := decryptor.Decrypt(ctx, att, ed.CipherKeyRef, ed.Ciphertext)
	if err != nil {
		return zero, err
	}

	var out T
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return zero, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, nil
}
