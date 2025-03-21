package o11y

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"sync"
	"time"
)

type SpanKind string

const (
	SpanKindInternal SpanKind = "internal"
	SpanKindServer   SpanKind = "server"
	SpanKindClient   SpanKind = "client"
)

type Span struct {
	Kind        SpanKind          `json:"kind,omitempty"`
	Name        string            `json:"name"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time,omitempty"`
	Children    []*Span           `json:"children,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Status      int               `json:"status,omitempty"`
	Logs        []json.RawMessage `json:"logs,omitempty"`

	mu sync.Mutex
}

type spanKey struct{}

func GetSpan(ctx context.Context) *Span {
	span, ok := ctx.Value(spanKey{}).(*Span)
	if !ok {
		return nil
	}
	return span
}

func Trace(ctx context.Context, name string, opts ...func(*Span)) (context.Context, *Span) {
	parent := GetSpan(ctx)
	span := &Span{
		Name:        name,
		StartTime:   time.Now(),
		Metadata:    make(map[string]any),
		Annotations: make(map[string]string),
	}
	if parent != nil {
		parent.mu.Lock()
		parent.Children = append(parent.Children, span)
		parent.mu.Unlock()
	}
	for _, opt := range opts {
		opt(span)
	}
	return context.WithValue(ctx, spanKey{}, span), span
}

func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndTime = time.Now()
}

func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Metadata["exception.type"] = typeStr(err)
	s.Metadata["exception.message"] = err.Error()

	stackTrace := make([]byte, 2048)
	n := runtime.Stack(stackTrace, false)
	s.Metadata["exception.stacktrace"] = string(stackTrace[0:n])
}

func (s *Span) SetMetadata(attrs map[string]any) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range attrs {
		s.Metadata[k] = v
	}
}

func (s *Span) SetAnnotation(key string, value string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Annotations[key] = value
}

func (s *Span) SetStatus(status int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
}

func (s *Span) Write(p []byte) (n int, err error) {
	s.Logs = append(s.Logs, json.RawMessage(p))
	return len(p), nil
}

func typeStr(v any) string {
	t := reflect.TypeOf(v)
	if t.PkgPath() == "" && t.Name() == "" {
		return t.String()
	}
	return t.PkgPath() + "." + t.Name()
}

func WithSpanKind(kind SpanKind) func(s *Span) {
	return func(s *Span) {
		s.Kind = kind
	}
}

func WithMetadata(attrs map[string]any) func(s *Span) {
	return func(s *Span) {
		s.SetMetadata(attrs)
	}
}

func WithAnnotation(key string, value string) func(s *Span) {
	return func(s *Span) {
		s.SetAnnotation(key, value)
	}
}
