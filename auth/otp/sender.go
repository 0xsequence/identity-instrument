package otp

import (
	"context"
)

type Sender interface {
	NormalizeRecipient(recipient string) (string, error)
	SendOTP(ctx context.Context, ecosystem string, recipient string, code string) error
}
