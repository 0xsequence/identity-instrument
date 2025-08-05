package signature

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/gowebpki/jcs"
)

// Middleware validates that the request params were signed by the given auth key.
// It does not attempt to validate the auth key itself.
//
// It expects the request body to be a JSON object with the following fields:
// - params: the parameters of the request
// - authKey: public key (or address) of the auth keypair (secp256k1 or secp256r1)
// - signature: the signature of the params using the auth key
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Params    json.RawMessage `json:"params"`
				AuthKey   *proto.Key      `json:"authKey"`
				Signature string          `json:"signature"`
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("failed to read request body: %w", err))
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("failed to unmarshal request body: %w", err))
				return
			}

			if req.Params == nil || len(req.Params) == 0 {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("params is required"))
				return
			}

			if req.AuthKey == nil || !req.AuthKey.IsValid() {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("valid auth key is required"))
				return
			}

			if req.Signature == "" {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("signature is required"))
				return
			}

			sigBytes := common.FromHex(req.Signature)
			canonical, err := jcs.Transform(req.Params)
			if err != nil {
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("failed to canonicalize params: %w", err))
				return
			}

			switch req.AuthKey.KeyType {
			case proto.KeyType_Secp256k1:
				if err := ValidateSecp256k1(req.AuthKey.Address, canonical, sigBytes); err != nil {
					proto.RespondWithError(w, proto.ErrInvalidSignature.WithCause(err))
					return
				}
			case proto.KeyType_Secp256r1:
				if err := ValidateSecp256r1(req.AuthKey.Address, canonical, sigBytes); err != nil {
					proto.RespondWithError(w, proto.ErrInvalidSignature.WithCause(err))
					return
				}
			default:
				proto.RespondWithError(w, proto.ErrInvalidRequest.WithCausef("unknown key type"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
