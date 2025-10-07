package attestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/go-chi/chi/v5/middleware"
)

var nonceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Middleware is an HTTP middleware that issues an attestation document request to the enclave's NSM.
// The result wrapped in the Attestation type is then set in the context available to subsequent handlers.
// It also sets the X-Attestation-Document HTTP header to the Base64-encoded representation of the document.
//
// If the HTTP request includes an X-Attestation-Nonce header, its value is sent to the NSM and included in
// the final attestation document.
func Middleware(enc *enclave.Enclave) func(http.Handler) http.Handler {
	runPreMiddleware := func(r *http.Request) (ctx context.Context, cancelFunc func() error, err error) {
		ctx, span := o11y.Trace(r.Context(), "attestation.Middleware")
		defer func() {
			span.RecordError(err)
			span.End()
		}()

		att, err := enc.GetAttestation(ctx, nil, nil)
		if err != nil {
			return nil, nil, err
		}

		return context.WithValue(r.Context(), contextKey, att), att.Close, nil
	}

	runPostMiddleware := func(w http.ResponseWriter, r *http.Request, body []byte, nonce []byte) (err error) {
		ctx, span := o11y.Trace(r.Context(), "attestation.Middleware")
		defer func() {
			span.RecordError(err)
			span.End()
		}()

		userData, err := generateUserData(r, body)
		if err != nil {
			return err
		}

		att, err := enc.GetAttestation(ctx, nonce, userData)
		if err != nil {
			return err
		}
		defer att.Close()

		w.Header().Set("X-Attestation-Document", base64.StdEncoding.EncodeToString(att.Document()))
		return nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqBody, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(reqBody))

			var nonce []byte
			if nonceVal := r.Header.Get("X-Attestation-Nonce"); nonceVal != "" {
				if len(nonceVal) > 32 {
					proto.RespondWithError(w, fmt.Errorf("X-Attestation-Nonce value cannot be longer than 32"))
					return
				}
				if !nonceRegex.MatchString(nonceVal) {
					proto.RespondWithError(w, fmt.Errorf("X-Attestation-Nonce value contains invalid characters"))
					return
				}

				nonce = []byte(nonceVal)
			}

			ctx, cancel, err := runPreMiddleware(r)
			if err != nil {
				proto.RespondWithError(w, err)
				return
			}
			defer cancel()

			var body bytes.Buffer
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			ww.Tee(&body)
			ww.Discard()

			next.ServeHTTP(ww, r.WithContext(ctx))

			r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
			if err := runPostMiddleware(ww, r, body.Bytes(), nonce); err != nil {
				proto.RespondWithError(w, err)
				return
			}

			w.WriteHeader(ww.Status())
			if _, err := body.WriteTo(w); err != nil {
				proto.RespondWithError(w, err)
			}
		})
	}
}
