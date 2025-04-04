package auth

import (
	"context"

	"github.com/0xsequence/identity-instrument/proto"
)

type StoreCommitmentFn func(context.Context, *proto.AuthCommitmentData) error

type Handler interface {
	Supports(identityType proto.IdentityType) bool

	Commit(
		ctx context.Context,
		authID proto.AuthID,
		commitment *proto.AuthCommitmentData,
		signer *proto.SignerData,
		authKey *proto.AuthKey,
		metadata map[string]string,
		storeFn StoreCommitmentFn,
	) (resVerifier string, loginHint string, challenge string, err error)

	Verify(
		ctx context.Context, commitment *proto.AuthCommitmentData, authKey *proto.AuthKey, answer string,
	) (proto.Identity, error)
}
