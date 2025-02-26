package proto

import (
	"fmt"
	"strings"
)

func (id AuthID) String() string {
	return strings.Join([]string{id.Ecosystem, string(id.AuthMode), string(id.IdentityType), id.Verifier}, "/")
}

func (id *AuthID) FromString(s string) error {
	parts := strings.SplitN(s, "/", 4)
	if len(parts) != 4 {
		return fmt.Errorf("invalid auth ID format: %s", s)
	}

	id.Ecosystem = parts[0]
	id.AuthMode = AuthMode(parts[1])
	id.IdentityType = IdentityType(parts[2])
	id.Verifier = parts[3]
	return nil
}
