package ecosystem

import (
	"context"
)

type contextKeyType string

var contextKey = contextKeyType("ecosystem")

func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKey).(string)
	return v
}
