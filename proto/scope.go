package proto

import (
	"fmt"
	"regexp"
)

var scopeRegex = regexp.MustCompile(`^@([0-9]+)(:[a-zA-Z0-9-_]+)?$`)

type Scope string

func (s Scope) String() string {
	return string(s)
}

func (s *Scope) FromString(str string) error {
	*s = Scope(str)
	return nil
}

func (s Scope) IsValid() bool {
	return scopeRegex.MatchString(string(s)) && len(s) <= 100
}

func (s Scope) Ecosystem() (string, error) {
	if !s.IsValid() {
		return "", fmt.Errorf("invalid scope: %s", s)
	}
	matches := scopeRegex.FindStringSubmatch(string(s))
	if len(matches) < 2 {
		return "", fmt.Errorf("invalid scope: %s", s)
	}
	ecosystem := matches[1]
	return ecosystem, nil
}

func (p *CommitVerifierParams) GetScope() Scope {
	return p.Scope
}

func (p *CompleteAuthParams) GetScope() Scope {
	return p.Scope
}

func (p *SignParams) GetScope() Scope {
	return p.Scope
}
