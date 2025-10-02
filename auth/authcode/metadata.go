package authcode

import (
	"fmt"
	"net/url"
	"strings"
)

type Metadata struct {
	Issuer      string
	Audience    string
	RedirectURI string
}

func ExtractMetadata(metadata map[string]string) (*Metadata, error) {
	if len(metadata) != 3 || metadata["iss"] == "" || metadata["aud"] == "" || metadata["redirect_uri"] == "" {
		return nil, fmt.Errorf("metadata must contain iss, aud, and redirect_uri")
	}

	issuer := strings.TrimSpace(metadata["iss"])
	if issuer == "" {
		return nil, fmt.Errorf("iss is required")
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	if parsedIssuer.Scheme != "https" {
		return nil, fmt.Errorf("issuer must be https")
	}

	audience := strings.TrimSpace(metadata["aud"])
	if audience == "" {
		return nil, fmt.Errorf("aud is required")
	}

	redirectURI := strings.TrimSpace(metadata["redirect_uri"])
	if redirectURI == "" {
		return nil, fmt.Errorf("redirect_uri is required")
	}
	if _, err := url.Parse(redirectURI); err != nil {
		return nil, fmt.Errorf("invalid redirect_uri: %w", err)
	}

	return &Metadata{
		Issuer:      issuer,
		Audience:    audience,
		RedirectURI: redirectURI,
	}, nil
}
