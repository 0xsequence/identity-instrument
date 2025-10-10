package kms

import (
	"context"
	"fmt"

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

	ciphertext := Ciphertext{
		EncryptedKey:  dataKey.Ciphertext,
		EncryptedData: encrypted,
	}

	encoded, err := ciphertext.Encode()
	if err != nil {
		return "", fmt.Errorf("encode ciphertext: %w", err)
	}
	return encoded, nil
}

func (k *RemoteKey) Decrypt(ctx context.Context, att *enclave.Attestation, ciphertext string) (_ []byte, err error) {
	ctx, span := o11y.Trace(ctx, "kms.RemoteKey.Decrypt", o11y.WithAnnotation("key_arn", k.keyARN))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	decoded, err := DecodeCiphertext(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	dataKey, err := att.Decrypt(ctx, decoded.EncryptedKey, []string{k.keyARN})
	if err != nil {
		return nil, fmt.Errorf("decrypt data key: %w", err)
	}

	plaintext, err := aescbc.Decrypt(dataKey, decoded.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
