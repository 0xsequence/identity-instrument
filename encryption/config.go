package encryption

import (
	"context"
	"io"
)

type Cryptor interface {
	CryptorID() string
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

type Config struct {
	PoolSize  int
	Threshold int
	Cryptors  map[string]Cryptor
}

func NewConfig(poolSize int, threshold int, cryptors []Cryptor) *Config {
	config := &Config{
		PoolSize:  poolSize,
		Threshold: threshold,
		Cryptors:  make(map[string]Cryptor),
	}

	for _, cryptor := range cryptors {
		config.Cryptors[cryptor.CryptorID()] = cryptor
	}

	return config
}

func (c *Config) areSharesValid(shares map[string]string) bool {
	// Check if the number of shares matches the number of cryptors
	if len(shares) != len(c.Cryptors) {
		return false
	}

	// Check if every key in shares exists in cryptors
	for shareKey := range shares {
		if _, exists := c.Cryptors[shareKey]; !exists {
			return false
		}
	}

	// Check if every key in cryptors exists in shares
	for cryptorKey := range c.Cryptors {
		if _, exists := shares[cryptorKey]; !exists {
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
