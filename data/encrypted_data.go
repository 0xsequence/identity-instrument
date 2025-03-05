package data

import (
	"context"
	"encoding/json"
	"fmt"
)

type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) (keyID string, ciphertext string, err error)
}

type Decryptor interface {
	Decrypt(ctx context.Context, keyID string, ciphertext string) ([]byte, error)
}

type EncryptedData[T any] struct {
	EncryptionKeyID string `dynamodbav:"EncryptionKeyID"`
	Ciphertext      string `dynamodbav:"Ciphertext"`
}

func Encrypt[T any](ctx context.Context, encryptor Encryptor, data T) (EncryptedData[T], error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return EncryptedData[T]{}, fmt.Errorf("marshal data: %w", err)
	}

	keyID, ciphertext, err := encryptor.Encrypt(ctx, plaintext)
	if err != nil {
		return EncryptedData[T]{}, err
	}

	ed := EncryptedData[T]{
		EncryptionKeyID: keyID,
		Ciphertext:      ciphertext,
	}
	return ed, nil
}

func (ed *EncryptedData[T]) Decrypt(ctx context.Context, decryptor Decryptor) (T, error) {
	var zero T

	plaintext, err := decryptor.Decrypt(ctx, ed.EncryptionKeyID, ed.Ciphertext)
	if err != nil {
		return zero, err
	}

	var out T
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return zero, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, nil
}
