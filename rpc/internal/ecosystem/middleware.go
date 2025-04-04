package ecosystem

import (
	"context"
	"fmt"
	"net/http"

	"github.com/0xsequence/identity-instrument/proto"
)

func Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ecosystem := r.Header.Get("X-Sequence-Ecosystem")
			if ecosystem == "" {
				proto.RespondWithError(w, fmt.Errorf("ecosystem is missing"))
				return
			}

			ctx := context.WithValue(r.Context(), contextKey, ecosystem)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
