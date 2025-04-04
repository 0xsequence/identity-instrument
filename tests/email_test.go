package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/proto/builder"
	proto "github.com/0xsequence/identity-instrument/proto/clients"
	"github.com/0xsequence/identity-instrument/rpc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmail(t *testing.T) {
	type assertionParams struct {
		svc       *rpc.RPC
		email     string
		attempt   int
		verifier  string
		challenge string
		signer    string
		loginHint string
	}

	testCases := map[string]struct {
		retryAttempts        int
		emailBuilder         func(t *testing.T, p assertionParams, unique string) string
		prepareCommitParams  func(t *testing.T, p assertionParams, cp *proto.CommitVerifierParams)
		assertCommitVerifier func(t *testing.T, p assertionParams, err error) bool
		extractAnswer        func(t *testing.T, p assertionParams) string
		assertCompleteAuth   func(t *testing.T, p assertionParams, err error) bool
	}{
		"Success": {
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
				require.NoError(t, err)
				require.NotEmpty(t, p.verifier)
				require.NotEmpty(t, p.challenge)
				return true
			},
			extractAnswer: func(t *testing.T, p assertionParams) string {
				subject, message, found := getSentEmailMessage(t, p.email)
				require.True(t, found)
				assert.Contains(t, "Login code for 123", subject)
				assert.Contains(t, message, "Your login code: ")
				return strings.TrimPrefix(message, "Your login code: ")
			},
			assertCompleteAuth: func(t *testing.T, p assertionParams, err error) bool {
				require.NoError(t, err)
				require.NotEmpty(t, p.signer)
				return true
			},
		},
		"IncorrectCode": {
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
				return true
			},
			extractAnswer: func(t *testing.T, p assertionParams) string {
				return "Wrong"
			},
			assertCompleteAuth: func(t *testing.T, p assertionParams, err error) bool {
				require.ErrorContains(t, err, "incorrect answer")
				return false
			},
		},
		"MultipleAttempts": {
			retryAttempts: 2,
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
				return true
			},
			extractAnswer: func(t *testing.T, p assertionParams) string {
				if p.attempt < 2 {
					return "Wrong"
				}
				_, message, found := getSentEmailMessage(t, p.email)
				require.True(t, found)
				return strings.TrimPrefix(message, "Your login code: ")
			},
			assertCompleteAuth: func(t *testing.T, p assertionParams, err error) bool {
				if p.attempt < 2 {
					require.ErrorContains(t, err, "incorrect answer")
					return false
				}
				require.NoError(t, err)
				return true
			},
		},
		// TODO: reenable after adding attempt tracking
		/*
			"TooManyAttempts": {
				retryAttempts: 10,
				assertInitiateAuth: func(t *testing.T, p assertionParams, err error) bool {
					return true
				},
				extractAnswer: func(t *testing.T, p assertionParams) string {
					if p.attempt < 3 {
						return "Wrong"
					}
					_, message, found := getSentEmailMessage(t, p.email)
					require.True(t, found)
					return strings.TrimPrefix(message, "Your login code: ")
				},
				assertRegisterAuth: func(t *testing.T, p assertionParams, err error) bool {
					if p.attempt < 3 {
						require.ErrorContains(t, err, "incorrect answer")
					} else {
						require.ErrorContains(t, err, "Too many attempts")
					}
					return false
				},
			},
		*/
		"UsingSigner": {
			prepareCommitParams: func(t *testing.T, p assertionParams, cp *proto.CommitVerifierParams) {
				cp.Handle = ""
				cp.Signer = insertSigner(t, p.svc, "123", "Email:"+p.email, p.email)
			},
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
				signer := deriveKey(t, p.email)
				require.NoError(t, err)
				require.NotEmpty(t, p.verifier)
				require.NotEmpty(t, p.challenge)
				assert.Equal(t, p.email, p.loginHint)
				assert.Equal(t, crypto.PubkeyToAddress(signer.PublicKey).Hex(), p.verifier)
				return true
			},
			extractAnswer: func(t *testing.T, p assertionParams) string {
				subject, message, found := getSentEmailMessage(t, p.email)
				require.True(t, found)
				assert.Contains(t, "Login code for 123", subject)
				assert.Contains(t, message, "Your login code: ")
				return strings.TrimPrefix(message, "Your login code: ")
			},
			assertCompleteAuth: func(t *testing.T, p assertionParams, err error) bool {
				signer := deriveKey(t, p.email)
				require.NoError(t, err)
				require.NotEmpty(t, p.signer)
				assert.Equal(t, crypto.PubkeyToAddress(signer.PublicKey).Hex(), p.signer)
				return true
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			builderServer := httptest.NewServer(builder.NewBuilderServer(builder.NewMock()))
			defer builderServer.Close()

			svc := initRPC(t, nil, func(cfg *config.Config) {
				cfg.Builder.BaseURL = builderServer.URL
			})

			authKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			require.NoError(t, err)

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			c := proto.NewIdentityInstrumentClient(srv.URL, http.DefaultClient)
			header := make(http.Header)
			ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
			require.NoError(t, err)

			var p assertionParams
			p.svc = svc

			unique := uuid.New().String()
			if testCase.emailBuilder != nil {
				p.email = testCase.emailBuilder(t, p, unique)
			} else {
				p.email = fmt.Sprintf("user+%s@example.com", unique)
			}

			commitParams := &proto.CommitVerifierParams{
				Ecosystem: "123",
				AuthKey: &proto.AuthKey{
					KeyType:   proto.KeyType_P256K1,
					PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
				},
				AuthMode:     proto.AuthMode_OTP,
				IdentityType: proto.IdentityType_Email,
				Handle:       p.email,
			}
			if testCase.prepareCommitParams != nil {
				testCase.prepareCommitParams(t, p, commitParams)
			}
			p.verifier, p.loginHint, p.challenge, err = c.CommitVerifier(ctx, commitParams)
			if testCase.assertCommitVerifier != nil {
				if proceed := testCase.assertCommitVerifier(t, p, err); !proceed {
					return
				}
			}

			var proceed bool
			for attempt := 0; attempt < testCase.retryAttempts+1; attempt++ {
				p.attempt = attempt

				code := testCase.extractAnswer(t, p)
				answer := hexutil.Encode(crypto.Keccak256([]byte(p.challenge + code)))

				completeParams := &proto.CompleteAuthParams{
					Ecosystem: "123",
					AuthKey: &proto.AuthKey{
						KeyType:   proto.KeyType_P256K1,
						PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
					},
					AuthMode:     proto.AuthMode_OTP,
					IdentityType: proto.IdentityType_Email,
					Verifier:     p.verifier,
					Answer:       answer,
				}
				p.signer, err = c.CompleteAuth(ctx, completeParams)
				if testCase.assertCompleteAuth != nil {
					proceed = testCase.assertCompleteAuth(t, p, err)
				}
			}
			if !proceed {
				return
			}

			digest := crypto.Keccak256([]byte("message"))
			digestHex := hexutil.Encode(digest)
			prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
			sig, err := crypto.Sign(prefixedHash, authKey)
			require.NoError(t, err)

			signParams := &proto.SignParams{
				Ecosystem: "123",
				AuthKey: &proto.AuthKey{
					KeyType:   proto.KeyType_P256K1,
					PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
				},
				Signer:    p.signer,
				Digest:    digestHex,
				Signature: hexutil.Encode(sig),
			}
			resSignature, err := c.Sign(ctx, signParams)
			require.NoError(t, err)

			sigBytes := common.FromHex(resSignature)
			if sigBytes[64] == 27 || sigBytes[64] == 28 {
				sigBytes[64] -= 27
			}

			pub, err := crypto.Ecrecover(digest, sigBytes)
			require.NoError(t, err)
			addr := common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
			assert.Equal(t, addr.String(), p.signer)
		})
	}
}
