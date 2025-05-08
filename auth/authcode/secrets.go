package authcode

import (
	"context"
)

type SecretProvider interface {
	GetClientSecret(ctx context.Context, ecosystem string, issuer string, audience string) (string, error)
}

type SecretProviderFunc func(ctx context.Context, ecosystem string, issuer string, audience string) (string, error)

func (f SecretProviderFunc) GetClientSecret(ctx context.Context, ecosystem string, issuer string, audience string) (string, error) {
	return f(ctx, ecosystem, issuer, audience)
}

type SecretConfig struct {
	Value       *string      `json:"value,omitempty"`
	GenerateJWT *GenerateJWT `json:"generate_jwt,omitempty"`
}

type GenerateJWT struct {
	Claims     JWTClaims  `json:"claims"`
	SigningKey SigningKey `json:"signing_key"`
}

type JWTClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
}

type SigningKey struct {
	KeyID      string `json:"kid"`
	Algorithm  string `json:"alg"`
	PrivateKey []byte `json:"private_key"`
}
