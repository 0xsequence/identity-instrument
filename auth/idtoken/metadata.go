package idtoken

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Metadata struct {
	Issuer    string
	Audience  string
	ExpiresAt time.Time
}

func ExtractMetadata(metadata map[string]string) (*Metadata, error) {
	if len(metadata) != 3 || metadata["iss"] == "" || metadata["aud"] == "" || metadata["exp"] == "" {
		return nil, fmt.Errorf("metadata must contain iss, aud, and exp")
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

	exp, err := strconv.ParseInt(metadata["exp"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse exp: %w", err)
	}
	expiresAt := time.Unix(exp, 0)

	return &Metadata{
		Issuer:    issuer,
		Audience:  audience,
		ExpiresAt: expiresAt,
	}, nil
}
