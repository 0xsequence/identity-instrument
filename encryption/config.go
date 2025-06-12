package encryption

import (
	"context"
	"io"

	"github.com/0xsequence/nitrocontrol/enclave"
)

type RemoteKey interface {
	RemoteKeyID() string
	Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, att *enclave.Attestation, ciphertext string) ([]byte, error)
}

type Config struct {
	PoolSize   int
	Threshold  int
	RemoteKeys map[string]RemoteKey
}

func NewConfig(poolSize int, threshold int, keys []RemoteKey) *Config {
	config := &Config{
		PoolSize:   poolSize,
		Threshold:  threshold,
		RemoteKeys: make(map[string]RemoteKey),
	}

	for _, key := range keys {
		config.RemoteKeys[key.RemoteKeyID()] = key
	}

	return config
}

func (c *Config) areSharesValid(shares map[string]string) bool {
	// Check if the number of shares matches the number of remote keys
	if len(shares) != len(c.RemoteKeys) {
		return false
	}

	// Check if every key in shares exists in remote keys
	for shareKey := range shares {
		if _, exists := c.RemoteKeys[shareKey]; !exists {
			return false
		}
	}

	// Check if every key in remote keys exists in shares
	for remoteKey := range c.RemoteKeys {
		if _, exists := shares[remoteKey]; !exists {
			return false
		}
	}

	return true
}

func (c *Config) randomKeyIndex(random io.Reader) (int, error) {
	// Generate a random number in the range [0, c.PoolSize-1]
	var buf [4]byte
	_, err := io.ReadFull(random, buf[:])
	if err != nil {
		return 0, err
	}

	// Convert bytes to uint32
	val := uint32(0)
	for _, b := range buf {
		val = (val << 8) | uint32(b)
	}

	// Take modulo to get value in range
	return int(val % uint32(c.PoolSize)), nil
}
