package email

import (
	"strings"
)

func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
