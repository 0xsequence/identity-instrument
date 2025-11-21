package idtoken

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

func withIssuer(expectedIss string, normalize bool) jwt.ValidatorFunc {
	return func(ctx context.Context, tok jwt.Token) jwt.ValidationError {
		iss := tok.Issuer()
		if normalize {
			iss = normalizeIssuer(iss)
		}

		if iss != expectedIss {
			return jwt.NewValidationError(fmt.Errorf("iss not satisfied"))
		}
		return nil
	}
}

func withAudience(expectedAudience []string) jwt.ValidatorFunc {
	return func(ctx context.Context, tok jwt.Token) jwt.ValidationError {
		tokAudiences := tok.Audience()
		for _, aud := range expectedAudience {
			if slices.Contains(tokAudiences, aud) {
				return nil
			}
		}

		return jwt.NewValidationError(fmt.Errorf("aud not satisfied"))
	}
}

func normalizeIssuer(iss string) string {
	if !strings.HasPrefix(iss, "https://") && !strings.HasPrefix(iss, "http://") {
		return "https://" + iss
	}
	iss = strings.TrimSuffix(iss, "/")
	return iss
}

func getEmailFromToken(tok jwt.Token) string {
	emailClaim, ok := tok.Get("email")
	if !ok {
		return ""
	}
	email, _ := emailClaim.(string)
	return email
}
