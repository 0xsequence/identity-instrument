package o11y

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/0xsequence/identity-instrument/proto"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/traceid"
)

func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body bytes.Buffer
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			ww.Tee(&body)
			ww.Discard()

			tid := traceid.FromContext(r.Context())
			ctx, span := Trace(
				r.Context(),
				r.URL.Path,
				WithSpanKind(SpanKindServer),
				WithMetadata(map[string]any{
					"sequence.traceid": tid,
					"net.host.name":    r.Host,
					"server.address":   r.Host,
					"http.method":      r.Method,
					"http.url":         r.URL.String(),
					"url.path":         r.URL.Path,
					"url.query":        r.URL.RawQuery,
				}),
			)

			next.ServeHTTP(ww, r.WithContext(ctx))

			span.SetStatus(ww.Status())
			span.End()
			spanJSON, err := json.Marshal(span)
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}

			w.Header().Set("X-Sequence-Span", string(spanJSON))

			w.WriteHeader(ww.Status())
			if _, err := body.WriteTo(w); err != nil {
				proto.RespondWithError(w, err)
			}
		})
	}
}
