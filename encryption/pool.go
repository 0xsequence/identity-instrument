package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/encryption/shamir"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/tee-verifier/nitro"
)

type Pool struct {
	enclave   *enclave.Enclave
	configs   []*Config
	keysTable *data.EncryptionPoolKeyTable
}

func NewPool(enc *enclave.Enclave, configs []*Config, keysTable *data.EncryptionPoolKeyTable) *Pool {
	return &Pool{
		enclave:   enc,
		configs:   configs,
		keysTable: keysTable,
	}
}

func (p *Pool) Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (_ string, _ string, err error) {
	ctx, span := o11y.Trace(ctx, "encryption.Pool.Encrypt")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	keyIndex, err := config.randomKeyIndex(att)
	if err != nil {
		return "", "", fmt.Errorf("random key index: %w", err)
	}
	span.SetAnnotation("key_index", strconv.Itoa(keyIndex))

	var privateKey []byte

	key, found, err := p.keysTable.Get(ctx, generation, keyIndex, false)
	if err != nil {
		return "", "", fmt.Errorf("get key: %w", err)
	}
	if !found {
		key, privateKey, err = p.generateKey(ctx, att, keyIndex)
		if err != nil {
			return "", "", fmt.Errorf("generate key: %w", err)
		}
	} else if err := p.verifyKey(ctx, att, key); err != nil {
		return "", "", fmt.Errorf("verify key: %w", err)
	}
	span.SetAnnotation("key_ref", key.KeyRef)

	if privateKey == nil {
		privateKey, err = p.combineShares(ctx, att, config, key.EncryptedShares)
		if err != nil {
			return "", "", fmt.Errorf("combine shares: %w", err)
		}
	}

	encrypted, err := aescbc.Encrypt(att, privateKey, plaintext)
	if err != nil {
		return "", "", fmt.Errorf("encrypt: %w", err)
	}

	ciphertextParts := []string{
		"v1",
		base64.RawURLEncoding.EncodeToString(encrypted),
	}

	return key.KeyRef, strings.Join(ciphertextParts, "."), nil
}

func (p *Pool) Decrypt(ctx context.Context, att *enclave.Attestation, keyRef string, ciphertext string) (_ []byte, err error) {
	ctx, span := o11y.Trace(ctx, "encryption.Pool.Decrypt", o11y.WithAnnotation("key_ref", keyRef))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	if parts[0] != "v1" {
		return nil, fmt.Errorf("unsupported ciphertext version")
	}

	encrypted, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}

	key, found, err := p.keysTable.GetLatestByKeyRef(ctx, keyRef, false)
	if err != nil {
		return nil, fmt.Errorf("get latest key: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("key not found")
	}
	if err := p.verifyKey(ctx, att, key); err != nil {
		return nil, fmt.Errorf("verify key: %w", err)
	}

	span.SetAnnotation("generation", strconv.Itoa(key.Generation))
	span.SetAnnotation("key_index", strconv.Itoa(key.KeyIndex))

	// TODO: verify attestation

	config, err := p.getConfig(key.Generation)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	if !config.areSharesValid(key.EncryptedShares) {
		return nil, fmt.Errorf("shares are invalid")
	}

	privateKey, err := p.combineShares(ctx, att, config, key.EncryptedShares)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}

	decrypted, err := aescbc.Decrypt(privateKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// TODO: rotate key if needed

	return decrypted, nil
}

func (p *Pool) currentConfig() (int, *Config) {
	index := len(p.configs) - 1
	return index, p.configs[index]
}

func (p *Pool) getConfig(configVersion int) (*Config, error) {
	if configVersion < 0 || configVersion >= len(p.configs) {
		return nil, fmt.Errorf("config version out of bounds")
	}
	return p.configs[configVersion], nil
}

func (p *Pool) generateKey(ctx context.Context, att *enclave.Attestation, keyIndex int) (_ *data.EncryptionPoolKey, _ []byte, err error) {
	ctx, span := o11y.Trace(ctx, "encryption.Pool.generateKey", o11y.WithAnnotation("key_index", strconv.Itoa(keyIndex)))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	// Generate a random AES-256 key (32 bytes) using the attestation as a source of randomness
	privateKey := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err = io.ReadFull(att, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	refBytes := make([]byte, 16)
	_, err = io.ReadFull(att, refBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key ref: %w", err)
	}
	keyRef := base64.RawURLEncoding.EncodeToString(refBytes)

	shares, err := shamir.Split(privateKey, len(config.Cryptors), config.Threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("split private key: %w", err)
	}

	i := 0
	encryptedShares := make(map[string]string)
	for cryptorID, cryptor := range config.Cryptors {
		encryptedShare, err := cryptor.Encrypt(ctx, att, shares[i])
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt share %d: %w", i, err)
		}
		encryptedShares[cryptorID] = encryptedShare
		i++
	}

	key := &data.EncryptionPoolKey{
		Generation:      generation,
		KeyIndex:        keyIndex,
		KeyRef:          keyRef,
		EncryptedShares: encryptedShares,
		CreatedAt:       time.Now(),
	}

	hash, err := key.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := p.enclave.GetAttestation(ctx, nil, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("get attestation: %w", err)
	}
	key.Attestation = keyAtt.Document()
	keyAtt.Close()

	alreadyExists, err := p.keysTable.Create(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create key: %w", err)
	}
	if alreadyExists {
		// The key was created by another instance. We need to get the latest key from the database.
		// This time, use a strongly consistent read.
		key, found, err := p.keysTable.GetLatestByKeyRef(ctx, keyRef, true)
		if err != nil {
			return nil, nil, fmt.Errorf("get latest key: %w", err)
		}
		if !found {
			return nil, nil, fmt.Errorf("key not found")
		}
		if err := p.verifyKey(ctx, att, key); err != nil {
			return nil, nil, fmt.Errorf("verify key: %w", err)
		}
		return key, privateKey, nil
	}

	return key, privateKey, nil
}

func (p *Pool) verifyKey(ctx context.Context, att *enclave.Attestation, key *data.EncryptionPoolKey) (err error) {
	ctx, span := o11y.Trace(ctx, "encryption.Pool.verifyKey")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	hash, err := key.Hash()
	if err != nil {
		return fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := nitro.Parse(key.Attestation)
	if err != nil {
		return fmt.Errorf("parse attestation: %w", err)
	}

	opts := []nitro.ValidateOption{
		nitro.WithExpectedUserData(hash),
		// attestation is stored long-term, so we can only ensure it was valid at the time of creation
		nitro.WithTime(keyAtt.Timestamp),
		// only accept attestations created by the same IAM role
		nitro.WithExpectedPCRs(map[int]string{
			3: att.PCRs[3], // PCR3 is the hash of the IAM role
		}),
		// expect the same root certificate as the one attested by the enclave
		nitro.WithRootFingerprint(att.RootCertFingerprint()),
	}
	if err := keyAtt.Validate(opts...); err != nil {
		return fmt.Errorf("validate attestation: %w", err)
	}

	if err := keyAtt.Verify(); err != nil {
		return fmt.Errorf("verify attestation: %w", err)
	}

	return nil
}

func (p *Pool) combineShares(ctx context.Context, att *enclave.Attestation, config *Config, shares map[string]string) (_ []byte, err error) {
	ctx, span := o11y.Trace(ctx, "encryption.Pool.combineShares")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	decryptedShares := make([][]byte, 0, len(shares))
	for cryptorID, encryptedShare := range shares {
		cryptor, ok := config.Cryptors[cryptorID]
		if !ok {
			return nil, fmt.Errorf("cryptor not found: %s", cryptorID)
		}
		decryptedShare, err := cryptor.Decrypt(ctx, att, encryptedShare)
		if err != nil {
			// TODO: log error?
			continue
		}
		decryptedShares = append(decryptedShares, decryptedShare)
	}

	privateKey, err := shamir.Combine(decryptedShares)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
