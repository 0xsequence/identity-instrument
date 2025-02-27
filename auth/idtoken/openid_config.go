package idtoken

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type OpenIDConfig struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURL       string `json:"jwks_uri"`
}

func (h *AuthHandler) GetOpenIDConfig(ctx context.Context, issuer string) (*OpenIDConfig, error) {
	ttl := 1 * time.Hour
	getter := func(ctx context.Context, _ string) (OpenIDConfig, error) {
		issuerConfigURL := normalizeIssuer(issuer) + "/.well-known/openid-configuration"
		req, err := http.NewRequest(http.MethodGet, issuerConfigURL, nil)
		if err != nil {
			return OpenIDConfig{}, err
		}

		resp, err := h.client.Do(req.WithContext(ctx))
		if err != nil {
			return OpenIDConfig{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return OpenIDConfig{}, errors.New("failed to fetch openid configuration")
		}

		var config OpenIDConfig
		if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
			return OpenIDConfig{}, err
		}
		return config, nil
	}

	openidConfig, err := h.openidConfigStore.GetOrSetWithLockEx(ctx, issuer, getter, ttl)
	if err != nil {
		return nil, err
	}
	return &openidConfig, nil
}
