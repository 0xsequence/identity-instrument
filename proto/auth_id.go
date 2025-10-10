package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func (id AuthID) Validate() error {
	if id.Scope == "" || strings.Contains(id.Scope.String(), "/") {
		return fmt.Errorf("invalid scope: %s", id.Scope)
	}
	if id.AuthMode == "" || strings.Contains(string(id.AuthMode), "/") {
		return fmt.Errorf("invalid auth mode: %s", id.AuthMode)
	}
	if id.IdentityType == "" || strings.Contains(string(id.IdentityType), "/") {
		return fmt.Errorf("invalid identity type: %s", id.IdentityType)
	}
	if id.Verifier == "" || strings.Contains(id.Verifier, "/") {
		return fmt.Errorf("invalid verifier: %s", id.Verifier)
	}
	if len(id.Verifier) > 250 {
		return fmt.Errorf("verifier is too long: %d", len(id.Verifier))
	}

	return nil
}

func (id AuthID) Encode() (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return strings.Join([]string{id.Scope.String(), string(id.AuthMode), string(id.IdentityType), id.Verifier}, "/"), nil
}

func (id *AuthID) FromString(s string) error {
	parts := strings.SplitN(s, "/", 4)
	if len(parts) != 4 {
		return fmt.Errorf("invalid auth ID format: %s", s)
	}

	id.Scope = Scope(parts[0])
	id.AuthMode = AuthMode(parts[1])
	id.IdentityType = IdentityType(parts[2])
	id.Verifier = parts[3]

	if err := id.Validate(); err != nil {
		return err
	}

	return nil
}

func (id *AuthID) Hash() (string, error) {
	encoded, err := id.Encode()
	if err != nil {
		return "", fmt.Errorf("encode auth ID: %w", err)
	}
	hash := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(hash[:]), nil
}
