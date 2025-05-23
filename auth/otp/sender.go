package otp

import (
	"context"

	"github.com/0xsequence/identity-instrument/proto"
)

type Sender interface {
	NormalizeRecipient(recipient string) (string, error)
	SendOTP(ctx context.Context, scope proto.Scope, recipient string, code string) error
}
