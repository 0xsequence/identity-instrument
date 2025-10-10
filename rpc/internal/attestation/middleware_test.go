package attestation_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	enc, err := enclave.New(context.Background(), enclave.DummyProvider(nil), nil)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(attestation.Middleware(enc)(handler))
	defer srv.Close()

	tests := map[string]struct {
		request     func() (http.Header, []byte)
		wantStatus  int
		wantErrText string
	}{
		"NoNonce": {
			wantStatus: http.StatusOK,
			request: func() (http.Header, []byte) {
				return http.Header{}, []byte("test")
			},
		},
		"ValidNonce": {
			wantStatus: http.StatusOK,
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"test"},
				}, []byte("test")
			},
		},
		"InvalidNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value contains invalid characters",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"!@#$%^&*()"},
				}, []byte("test")
			},
		},
		"LongNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value cannot be longer than 32",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"test-123456789012345678901234567890123"},
				}, []byte("test")
			},
		},
		"WhitespaceNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value contains invalid characters",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"   \t a  a \t  "},
				}, []byte("test")
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			header, reqBody := test.request()
			req, err := http.NewRequest("POST", srv.URL, bytes.NewBuffer(reqBody))
			require.NoError(t, err)
			req.Header = header

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, resp.Body.Close())
			}()
			body, _ := io.ReadAll(resp.Body)

			require.Equal(t, test.wantStatus, resp.StatusCode, string(body))
			if test.wantErrText != "" {
				require.Contains(t, string(body), test.wantErrText)
			}
		})
	}
}
