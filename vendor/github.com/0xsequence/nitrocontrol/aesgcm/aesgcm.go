// Package aesgcm contains utility functions to Encrypt and Decrypt data using AES-256-GCM cipher.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using key and random entropy. Key must be a valid AES-256 key with a length of 32 bytes.
// The result is a concatenation of nonce (using standard 12-byte nonce size) and the actual ciphertext.
func Encrypt(random io.Reader, key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256 but was %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher block: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("generate random nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts ciphertext using the given key. Key must be a valid AES-256 key with a length of 32 bytes.
// Ciphertext is assumed to be a concatenation of nonce (using standard 12-byte nonce size) and the actual
// ciphertext. As such, it must be at least 12 bytes long.
func Decrypt(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256 but was %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher block: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext must be at least %d bytes but was %d", aead.NonceSize(), len(ciphertext))
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	plaintext := make([]byte, 0, len(ciphertext))

	plaintext, err = aead.Open(plaintext, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
