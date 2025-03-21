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

func (t *tracedRPC) InitiateAuth(ctx context.Context, params *proto.InitiateAuthParams) (_ string, _ string, err error) {
	ctx, span := Trace(ctx, "InitiateAuth")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.InitiateAuth(ctx, params)
}

func (t *tracedRPC) RegisterAuth(ctx context.Context, params *proto.RegisterAuthParams) (_ string, err error) {
	ctx, span := Trace(ctx, "RegisterAuth")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.RegisterAuth(ctx, params)
}

func (t *tracedRPC) Sign(ctx context.Context, params *proto.SignParams) (_ string, err error) {
	ctx, span := Trace(ctx, "Sign")
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return t.svc.Sign(ctx, params)
}
