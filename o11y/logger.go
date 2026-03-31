package o11y

import (
	"context"
	"log/slog"

	identityinstrument "github.com/0xsequence/identity-instrument"
	"github.com/0xsequence/nitrocontrol/tracing"
)

func LoggerFromContext(ctx context.Context) *slog.Logger {
	span := tracing.GetSpan(ctx)
	return slog.New(slog.NewJSONHandler(span, nil)).With("app_version", identityinstrument.VERSION)
}
