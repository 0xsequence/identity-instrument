package data

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type EncryptedData[T any] struct {
	encryptedKey []byte
	algorithm    string
	ciphertext   []byte
}

func Encrypt[T any](ctx context.Context, att *enclave.Attestation, keyID string, data T) (EncryptedData[T], error) {
	dk, err := att.GenerateDataKey(ctx, keyID)
	if err != nil {
		return EncryptedData[T]{}, err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return EncryptedData[T]{}, fmt.Errorf("marshal data: %w", err)
	}

	ciphertext, err := aescbc.Encrypt(att, dk.Plaintext, plaintext)
	if err != nil {
		return EncryptedData[T]{}, fmt.Errorf("AES encrypt: %w", err)
	}
	ed := EncryptedData[T]{
		encryptedKey: dk.Ciphertext,
		algorithm:    "AES-256",
		ciphertext:   ciphertext,
	}
	return ed, nil
}

func (ed *EncryptedData[T]) Decrypt(ctx context.Context, att *enclave.Attestation, keyIDs []string) (T, error) {
	var zero T

	dk, err := att.Decrypt(ctx, ed.encryptedKey, keyIDs)
	if err != nil {
		return zero, err
	}

	payloadBytes, err := aescbc.Decrypt(dk, ed.ciphertext)
	if err != nil {
		return zero, fmt.Errorf("AES decrypt: %w", err)
	}

	var out T
	if err := json.Unmarshal(payloadBytes, &out); err != nil {
		return zero, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, nil
}

func (ed *EncryptedData[T]) String() string {
	parts := []string{
		ed.algorithm,
		base64.StdEncoding.EncodeToString(ed.encryptedKey),
		base64.StdEncoding.EncodeToString(ed.ciphertext),
	}
	return strings.Join(parts, ":")
}

func (ed *EncryptedData[T]) FromString(s string) error {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return fmt.Errorf("invalid encrypted data format: %s", s)
	}
	ed.algorithm = parts[0]
	ed.encryptedKey, _ = base64.StdEncoding.DecodeString(parts[1])
	ed.ciphertext, _ = base64.StdEncoding.DecodeString(parts[2])
	return nil
}

func (ed *EncryptedData[T]) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberS{Value: ed.String()}, nil
}

func (ed *EncryptedData[T]) UnmarshalDynamoDBAttributeValue(value types.AttributeValue) error {
	v, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		return fmt.Errorf("invalid encrypted data type: %T", value)
	}
	return ed.FromString(v.Value)
}
