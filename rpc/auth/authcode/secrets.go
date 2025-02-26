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
