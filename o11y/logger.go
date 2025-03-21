package o11y

import (
	"context"
	"log/slog"
)

func LoggerFromContext(ctx context.Context) *slog.Logger {
	span := GetSpan(ctx)
	return slog.New(slog.NewJSONHandler(span, nil))
}
