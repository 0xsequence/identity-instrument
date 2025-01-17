package oidc

import (
	"context"
	"encoding/json"
	"errors"
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

func fetchJWKSURL(ctx context.Context, client HTTPClient, iss string) (string, error) {
	// Construct the URL to the issuer's .well-known/openid-configuration endpoint
	issuerConfigURL := normalizeIssuer(iss) + "/.well-known/openid-configuration"

	req, err := http.NewRequest(http.MethodGet, issuerConfigURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch openid configuration")
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}

	jwksURI, ok := config["jwks_uri"].(string)
	if !ok {
		return "", errors.New("jwks_uri not found in openid configuration")
	}

	return jwksURI, nil
}

func normalizeIssuer(iss string) string {
	if !strings.HasPrefix(iss, "https://") && !strings.HasPrefix(iss, "http://") {
		return "https://" + iss
	}
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
