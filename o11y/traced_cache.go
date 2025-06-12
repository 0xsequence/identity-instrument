package o11y

import (
	"context"
	"time"

	"github.com/goware/cachestore"
)

type tracedCache[V any] struct {
	label string
	cachestore.Store[V]
}

func NewTracedCache[V any](label string, store cachestore.Store[V]) cachestore.Store[V] {
	return &tracedCache[V]{label: label, Store: store}
}

func (c *tracedCache[V]) GetOrSetWithLock(ctx context.Context, key string, getter func(context.Context, string) (V, error)) (_ V, err error) {
	ctx, span := Trace(ctx, "cachestore.GetOrSetWithLock", WithAnnotation("cache", c.label))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	source := "cache"
	tracedGetter := func(ctx context.Context, key string) (V, error) {
		source = "remote"
		return getter(ctx, key)
	}

	span.SetAnnotation("source", source)

	return c.Store.GetOrSetWithLock(ctx, key, tracedGetter)
}

func (c *tracedCache[V]) GetOrSetWithLockEx(ctx context.Context, key string, getter func(context.Context, string) (V, error), ttl time.Duration) (_ V, err error) {
	ctx, span := Trace(ctx, "cachestore.GetOrSetWithLockEx", WithAnnotation("cache", c.label))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	source := "cache"
	tracedGetter := func(ctx context.Context, key string) (V, error) {
		source = "remote"
		return getter(ctx, key)
	}

	span.SetAnnotation("source", source)

	return c.Store.GetOrSetWithLockEx(ctx, key, tracedGetter, ttl)
}
