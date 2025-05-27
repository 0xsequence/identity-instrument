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

func (t *tracedRPC) CommitVerifier(ctx context.Context, params *proto.CommitVerifierParams) (_ string, _ string, _ string, err error) {
	ctx, span := Trace(ctx, "CommitVerifier")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.CommitVerifier(ctx, params)
}

func (t *tracedRPC) CompleteAuth(ctx context.Context, params *proto.CompleteAuthParams) (_ *proto.Key, _ *proto.Identity, err error) {
	ctx, span := Trace(ctx, "CompleteAuth")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.CompleteAuth(ctx, params)
}

func (t *tracedRPC) Sign(ctx context.Context, params *proto.SignParams) (_ string, err error) {
	ctx, span := Trace(ctx, "Sign")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.Sign(ctx, params)
}
