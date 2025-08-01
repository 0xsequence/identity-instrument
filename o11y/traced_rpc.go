package o11y

import (
	"context"

	proto "github.com/0xsequence/identity-instrument/proto"
)

type tracedRPC struct {
	svc proto.IdentityInstrument
}

var _ proto.IdentityInstrument = (*tracedRPC)(nil)

func NewTracedRPC(svc proto.IdentityInstrument) *tracedRPC {
	return &tracedRPC{svc: svc}
}

func (t *tracedRPC) CommitVerifier(ctx context.Context, params *proto.CommitVerifierParams, authKey *proto.Key, signature string) (_ string, _ string, _ string, err error) {
	ctx, span := Trace(ctx, "CommitVerifier")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.CommitVerifier(ctx, params, authKey, signature)
}

func (t *tracedRPC) CompleteAuth(ctx context.Context, params *proto.CompleteAuthParams, authKey *proto.Key, signature string) (_ *proto.Key, _ *proto.Identity, err error) {
	ctx, span := Trace(ctx, "CompleteAuth")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.CompleteAuth(ctx, params, authKey, signature)
}

func (t *tracedRPC) Sign(ctx context.Context, params *proto.SignParams, authKey *proto.Key, signature string) (_ string, err error) {
	ctx, span := Trace(ctx, "Sign")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.Sign(ctx, params, authKey, signature)
}
