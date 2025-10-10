package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func (id Identity) Validate() error {
	switch id.Type {
	case IdentityType_Email:
		if id.Subject == "" {
			return fmt.Errorf("email subject cannot be empty")
		}
	case IdentityType_OIDC:
		if id.Issuer == "" {
			return fmt.Errorf("OIDC issuer cannot be empty")
		}
		if strings.Contains(id.Issuer, "#") {
			return fmt.Errorf("OIDC issuer cannot contain fragment (#)")
		}
		if id.Subject == "" {
			return fmt.Errorf("OIDC subject cannot be empty")
		}
	}
	return nil
}

func (id Identity) Encode() (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}

	switch id.Type {
	case IdentityType_Email:
		return string(id.Type) + ":" + id.Subject, nil
	case IdentityType_OIDC:
		return string(id.Type) + ":" + id.Issuer + "#" + id.Subject, nil
	default:
		return "", fmt.Errorf("invalid identity type: %s", id.Type)
	}
}

func (id *Identity) FromString(s string) error {
	// Split on the first ':' only, the other may occur naturally in the issuer URL
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid identity format: %s", s)
	}

	idType := IdentityType(parts[0])
	switch idType {
	case IdentityType_OIDC:
		// Split on the first '#' only, the other may occur naturally in the subject
		innerParts := strings.SplitN(parts[1], "#", 2)
		if len(innerParts) != 2 {
			return fmt.Errorf("invalid identity format: %s", parts[1])
		}
		id.Type = idType
		id.Issuer = innerParts[0]
		id.Subject = innerParts[1]

	case IdentityType_Email:
		id.Type = IdentityType_Email
		id.Subject = parts[1]

	default:
		return fmt.Errorf("invalid identity type: %s", parts[0])
	}

	// Validate the parsed identity
	if err := id.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	return nil
}

func (id *Identity) Hash() (string, error) {
	encoded, err := id.Encode()
	if err != nil {
		return "", fmt.Errorf("encode identity: %w", err)
	}
	hash := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(hash[:]), nil
}
