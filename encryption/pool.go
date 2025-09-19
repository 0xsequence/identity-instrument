package encryption

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
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

type KeysTable interface {
	Get(ctx context.Context, generation int, keyIndex int, consistentRead bool) (*data.CipherKey, bool, error)
	GetLatestByKeyRef(ctx context.Context, keyRef string, consistentRead bool) (*data.CipherKey, bool, error)
	Create(ctx context.Context, key *data.CipherKey) (bool, error)
}

type Attester interface {
	GetAttestation(ctx context.Context, nonce []byte, userData []byte) (*enclave.Attestation, error)
}

type Pool struct {
	attester  Attester
	configs   []*Config
	keysTable KeysTable
}

func NewPool(attester Attester, configs []*Config, keysTable KeysTable) *Pool {
	return &Pool{
		attester:  attester,
		configs:   configs,
		keysTable: keysTable,
	}
}

func (p *Pool) Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (_ string, _ string, err error) {
	log := o11y.LoggerFromContext(ctx)
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
		log.Info("generating new cipher key", "generation", generation, "key_index", keyIndex)

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
	log := o11y.LoggerFromContext(ctx)
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

	if p.keyNeedsMigration(key) {
		err := p.migrateKey(ctx, att, key, privateKey)
		if err != nil {
			// We don't want to fail the decryption if migration fails, log the error and continue
			log.Error("migrating key failed", "error", err, "key_ref", key.KeyRef, "generation", key.Generation, "key_index", key.KeyIndex)
		}
	}

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

func (p *Pool) generateKey(ctx context.Context, att *enclave.Attestation, keyIndex int) (_ *data.CipherKey, _ []byte, err error) {
	log := o11y.LoggerFromContext(ctx)
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

	shares, err := shamir.Split(privateKey, len(config.RemoteKeys), config.Threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("split private key: %w", err)
	}

	i := 0
	encryptedShares := make(map[string]string)
	for remoteKeyID, remoteKey := range config.RemoteKeys {
		encryptedShare, err := remoteKey.Encrypt(ctx, att, shares[i])
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt share %d: %w", i, err)
		}
		encryptedShares[remoteKeyID] = encryptedShare
		i++
	}

	key := &data.CipherKey{
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

	keyAtt, err := p.attester.GetAttestation(ctx, nil, hash)
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
		log.Info("attempted to create key that already exists", "key_ref", keyRef, "generation", generation, "key_index", keyIndex)

		// The key was created by another instance. We need to get the latest key from the database.
		// This time, use a strongly consistent read.
		existingKey, found, err := p.keysTable.Get(ctx, generation, keyIndex, true)
		if err != nil {
			return nil, nil, fmt.Errorf("get latest key: %w", err)
		}
		if !found {
			return nil, nil, fmt.Errorf("key not found")
		}
		if err := p.verifyKey(ctx, att, key); err != nil {
			return nil, nil, fmt.Errorf("verify key: %w", err)
		}

		// Return nil private key so that the caller decrypts the existingKey shares
		return existingKey, nil, nil
	}

	return key, privateKey, nil
}

func (p *Pool) verifyKey(ctx context.Context, att *enclave.Attestation, key *data.CipherKey) (err error) {
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

func (p *Pool) keyNeedsMigration(key *data.CipherKey) bool {
	generation, _ := p.currentConfig()
	return key.Generation < generation
}

func (p *Pool) migrateKey(ctx context.Context, att *enclave.Attestation, key *data.CipherKey, privateKey []byte) (err error) {
	log := o11y.LoggerFromContext(ctx)
	ctx, span := o11y.Trace(ctx, "encryption.Pool.migrateKey")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	log.Info("migrating key", "key_ref", key.KeyRef, "generation", key.Generation, "key_index", key.KeyIndex, "new_generation", generation)

	shares, err := shamir.Split(privateKey, len(config.RemoteKeys), config.Threshold)
	if err != nil {
		return fmt.Errorf("split private key: %w", err)
	}

	i := 0
	encryptedShares := make(map[string]string)
	for remoteKeyID, remoteKey := range config.RemoteKeys {
		encryptedShare, err := remoteKey.Encrypt(ctx, att, shares[i])
		if err != nil {
			return fmt.Errorf("encrypt share %d: %w", i, err)
		}
		encryptedShares[remoteKeyID] = encryptedShare
		i++
	}

	// Generate a random negative key index (to avoid collision with positive indices).
	var keyIndex int
	{
		var b [8]byte
		_, err := io.ReadFull(att, b[:])
		if err != nil {
			return fmt.Errorf("read random bytes for keyIndex: %w", err)
		}
		// Convert bytes to uint64, then to int and make negative
		// Use modulo to ensure the value fits in int64 range before conversion
		randomUint64 := binary.BigEndian.Uint64(b[:])
		keyIndex = -int(randomUint64 % math.MaxInt64)
	}

	migratedKey := &data.CipherKey{
		Generation:      generation,
		KeyIndex:        keyIndex,
		KeyRef:          key.KeyRef,
		EncryptedShares: encryptedShares,
		CreatedAt:       key.CreatedAt,
	}

	hash, err := migratedKey.Hash()
	if err != nil {
		return fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := p.attester.GetAttestation(ctx, nil, hash)
	if err != nil {
		return fmt.Errorf("get attestation: %w", err)
	}
	migratedKey.Attestation = keyAtt.Document()
	keyAtt.Close()

	alreadyExists, err := p.keysTable.Create(ctx, migratedKey)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	// We don't care if we encounter an index collision.
	// Either the random key index is already taken (unlikely) or the key was already migrated by another instance.
	// In either case, we bail here. If migration is still needed, it will be attempted again in the future.
	if alreadyExists {
		log.Info("attempted to migrate key that already exists", "key_ref", key.KeyRef, "generation", generation, "key_index", keyIndex)
	}

	return nil
}

func (p *Pool) combineShares(ctx context.Context, att *enclave.Attestation, config *Config, shares map[string]string) (_ []byte, err error) {
	log := o11y.LoggerFromContext(ctx)
	ctx, span := o11y.Trace(ctx, "encryption.Pool.combineShares")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	decryptedShares := make([][]byte, 0, len(shares))
	for remoteKeyID, encryptedShare := range shares {
		remoteKey, ok := config.RemoteKeys[remoteKeyID]
		if !ok {
			return nil, fmt.Errorf("remote key not found: %s", remoteKeyID)
		}
		decryptedShare, err := remoteKey.Decrypt(ctx, att, encryptedShare)
		if err != nil {
			log.Error("decrypt share failed", "error", err, "remote_key_id", remoteKeyID)
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
