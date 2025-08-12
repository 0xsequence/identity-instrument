package signature_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/internal/signature"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(signature.Middleware()(handler))
	defer srv.Close()

	tests := map[string]struct {
		body        func() []byte
		wantStatus  int
		wantErrText string
	}{
		"ValidSecp256k1": {
			wantStatus: http.StatusOK,
			body: func() []byte {
				priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
				require.NoError(t, err)

				address := crypto.PubkeyToAddress(priv.PublicKey).Hex()

				params := `{"foo":"bar"}`
				digest := crypto.Keccak256([]byte(params))
				digestHex := hexutil.Encode(digest)
				prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
				sig, err := crypto.Sign(prefixedHash, priv)
				require.NoError(t, err)

				authKey := &proto.Key{
					Address: address,
					KeyType: proto.KeyType_Secp256k1,
				}
				return makeBody(params, authKey, hexutil.Encode(sig))
			},
		},
		"ValidSecp256r1": {
			wantStatus: http.StatusOK,
			body: func() []byte {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				pubKeyHex := marshalPublicKey(&priv.PublicKey)

				params := `{"foo":"bar"}`
				hash := sha256.Sum256([]byte(params))
				r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
				require.NoError(t, err)

				sig := make([]byte, 64)
				copy(sig[0:32], r.Bytes())
				copy(sig[32:64], s.Bytes())

				authKey := &proto.Key{
					Address: pubKeyHex,
					KeyType: proto.KeyType_Secp256r1,
				}
				return makeBody(params, authKey, hexutil.Encode(sig))
			},
		},
		"NoBody": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "failed to unmarshal request body",
			body: func() []byte {
				return nil
			},
		},
		"NoParams": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "params is required",
			body: func() []byte {
				priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
				require.NoError(t, err)
				address := crypto.PubkeyToAddress(priv.PublicKey).Hex()

				authKey := &proto.Key{
					Address: address,
					KeyType: proto.KeyType_Secp256k1,
				}
				sig := make([]byte, 65)
				return makeBody("", authKey, hexutil.Encode(sig))
			},
		},
		"NoAuthKey": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "valid auth key is required",
			body: func() []byte {
				sig := make([]byte, 65)
				return makeBody("{}", nil, hexutil.Encode(sig))
			},
		},
		"InvalidAuthKey": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "valid auth key is required",
			body: func() []byte {
				sig := make([]byte, 65)
				return makeBody("{}", &proto.Key{Address: "0x123", KeyType: proto.KeyType("invalid")}, hexutil.Encode(sig))
			},
		},
		"NoSignature": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "signature is required",
			body: func() []byte {
				priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
				require.NoError(t, err)
				address := crypto.PubkeyToAddress(priv.PublicKey).Hex()

				authKey := &proto.Key{
					Address: address,
					KeyType: proto.KeyType_Secp256k1,
				}
				return makeBody("{}", authKey, "")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest("POST", srv.URL, bytes.NewBuffer(tt.body()))
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			require.Equal(t, tt.wantStatus, resp.StatusCode, string(body))
			if tt.wantErrText != "" {
				require.Contains(t, string(body), tt.wantErrText)
			}
		})
	}
}

func makeBody(params string, authKey *proto.Key, signature string) []byte {
	body := struct {
		Params    json.RawMessage `json:"params,omitempty"`
		AuthKey   *proto.Key      `json:"authKey,omitempty"`
		Signature string          `json:"signature,omitempty"`
	}{
		Params:    json.RawMessage(params),
		AuthKey:   authKey,
		Signature: signature,
	}
	b, _ := json.Marshal(body)
	return b
}
