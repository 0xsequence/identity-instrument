package o11y

import (
	"context"

	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/proto"
)

type tracedAuthHandler struct {
	name string
	auth.Handler
}

func NewTracedAuthHandler(name string, handler auth.Handler) auth.Handler {
	return &tracedAuthHandler{name: name, Handler: handler}
}

// Commit implements auth.Handler.
func (t *tracedAuthHandler) Commit(
	ctx context.Context,
	authID proto.AuthID,
	commitment *proto.AuthCommitmentData,
	signer *proto.SignerData,
	authKey *proto.AuthKey,
	metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (_ string, _ string, _ string, err error) {
	ctx, span := Trace(ctx, t.name+".Commit")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.Handler.Commit(ctx, authID, commitment, signer, authKey, metadata, storeFn)
}

// Verify implements auth.Handler.
func (t *tracedAuthHandler) Verify(ctx context.Context, commitment *proto.AuthCommitmentData, authKey *proto.AuthKey, answer string) (_ proto.Identity, err error) {
	ctx, span := Trace(ctx, t.name+".Verify")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.Handler.Verify(ctx, commitment, authKey, answer)
}
