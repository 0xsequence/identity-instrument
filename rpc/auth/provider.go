package auth

import (
	"context"

	"github.com/0xsequence/identity-instrument/proto"
)

type StoreCommitmentFn func(context.Context, *proto.AuthCommitmentData) error

type Provider interface {
	InitiateAuth(
		ctx context.Context,
		commitment *proto.AuthCommitmentData,
		ecosystemID string,
		verifier string,
		authKey *proto.AuthKey,
		storeFn StoreCommitmentFn,
	) (*proto.InitiateAuthResponse, error)

	Verify(
		ctx context.Context, commitment *proto.AuthCommitmentData, authKey *proto.AuthKey, answer string,
	) (proto.Identity, error)
}
