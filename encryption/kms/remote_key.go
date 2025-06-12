package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
)

type RemoteKey struct {
	keyARN string
}

func NewRemoteKey(keyARN string) *RemoteKey {
	return &RemoteKey{
		keyARN: keyARN,
	}
}

func (k *RemoteKey) RemoteKeyID() string {
	return "awskms|" + k.keyARN
}

func (k *RemoteKey) Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (_ string, err error) {
	ctx, span := o11y.Trace(ctx, "kms.RemoteKey.Encrypt", o11y.WithAnnotation("key_arn", k.keyARN))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

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

func (k *RemoteKey) Decrypt(ctx context.Context, att *enclave.Attestation, ciphertext string) (_ []byte, err error) {
	ctx, span := o11y.Trace(ctx, "kms.RemoteKey.Decrypt", o11y.WithAnnotation("key_arn", k.keyARN))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

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
