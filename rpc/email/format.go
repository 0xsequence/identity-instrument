package email

import (
	"fmt"
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func Validate(email string) error {
	if len(email) > 254 {
		return fmt.Errorf("too long")
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("incorrect format")
	}
	return nil
}
