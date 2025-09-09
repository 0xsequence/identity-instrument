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
		signer    *proto.Key
		identity  *proto.Identity
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
				require.NotEmpty(t, p.identity)
				assert.Equal(t, p.identity.Type, proto.IdentityType_Email)
				assert.Equal(t, p.identity.Subject, p.email)
				assert.Equal(t, p.identity.Email, p.email)
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
				require.ErrorContains(t, err, "answer is incorrect")
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
					require.ErrorContains(t, err, "answer is incorrect")
					return false
				}
				require.NoError(t, err)
				return true
			},
		},
		"TooManyAttempts": {
			retryAttempts: 10,
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
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
			assertCompleteAuth: func(t *testing.T, p assertionParams, err error) bool {
				if p.attempt < 2 {
					require.ErrorContains(t, err, "answer is incorrect")
				} else {
					require.ErrorContains(t, err, "Too many attempts")
				}
				return false
			},
		},
		"UsingSigner": {
			prepareCommitParams: func(t *testing.T, p assertionParams, cp *proto.CommitVerifierParams) {
				signer := insertSigner(t, p.svc, "123", "Email:"+p.email, p.email)
				cp.Handle = ""
				cp.Signer = &proto.Key{
					KeyType: proto.KeyType_Ethereum_Secp256k1,
					Address: signer.Address,
				}
			},
			assertCommitVerifier: func(t *testing.T, p assertionParams, err error) bool {
				signer := deriveKey(t, p.email)
				signerAddr := strings.ToLower(crypto.PubkeyToAddress(signer.PublicKey).Hex())
				require.NoError(t, err)
				require.NotEmpty(t, p.verifier)
				require.NotEmpty(t, p.challenge)
				assert.Equal(t, p.email, p.loginHint)
				assert.Equal(t, "Ethereum_Secp256k1:"+signerAddr, p.verifier)
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
				signerAddr := strings.ToLower(crypto.PubkeyToAddress(signer.PublicKey).Hex())
				require.NoError(t, err)
				require.NotEmpty(t, p.signer)
				assert.Equal(t, "Ethereum_Secp256k1:"+signerAddr, p.signer.String())
				return true
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			builderServer := httptest.NewServer(builder.NewEcosystemManagerServer(builder.NewMock()))
			defer builderServer.Close()

			svc := initRPC(t, nil, func(cfg *config.Config) {
				cfg.Builder.BaseURL = builderServer.URL
			})

			authKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			require.NoError(t, err)

			srv := httptest.NewServer(svc.Handler())
			defer srv.Close()

			c := proto.NewIdentityInstrumentClient(srv.URL, http.DefaultClient)

			var p assertionParams
			p.svc = svc

			unique := uuid.New().String()
			if testCase.emailBuilder != nil {
				p.email = testCase.emailBuilder(t, p, unique)
			} else {
				p.email = fmt.Sprintf("user+%s@example.com", unique)
			}

			protoAuthKey := &proto.Key{
				KeyType: proto.KeyType_Ethereum_Secp256k1,
				Address: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
			}
			commitParams := &proto.CommitVerifierParams{
				Scope:        proto.Scope("@123"),
				AuthMode:     proto.AuthMode_OTP,
				IdentityType: proto.IdentityType_Email,
				Handle:       p.email,
			}
			if testCase.prepareCommitParams != nil {
				testCase.prepareCommitParams(t, p, commitParams)
			}
			sig := signRequest(t, authKey, commitParams)
			p.verifier, p.loginHint, p.challenge, err = c.CommitVerifier(ctx, commitParams, protoAuthKey, sig)
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
					Scope:        proto.Scope("@123"),
					AuthMode:     proto.AuthMode_OTP,
					IdentityType: proto.IdentityType_Email,
					SignerType:   proto.KeyType_Ethereum_Secp256k1,
					Verifier:     p.verifier,
					Answer:       answer,
				}
				sig = signRequest(t, authKey, completeParams)
				p.signer, p.identity, err = c.CompleteAuth(ctx, completeParams, protoAuthKey, sig)
				if testCase.assertCompleteAuth != nil {
					proceed = testCase.assertCompleteAuth(t, p, err)
				}
			}
			if !proceed {
				return
			}

			digest := crypto.Keccak256([]byte("message"))
			signParams := &proto.SignParams{
				Scope:  proto.Scope("@123"),
				Signer: *p.signer,
				Digest: hexutil.Encode(digest),
			}
			sig = signRequest(t, authKey, signParams)
			resSignature, err := c.Sign(ctx, signParams, protoAuthKey, sig)
			require.NoError(t, err)

			sigBytes := common.FromHex(resSignature)
			if sigBytes[64] == 27 || sigBytes[64] == 28 {
				sigBytes[64] -= 27
			}

			pub, err := crypto.Ecrecover(digest, sigBytes)
			require.NoError(t, err)
			addr := common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
			assert.Equal(t, "Ethereum_Secp256k1:"+strings.ToLower(addr.Hex()), p.signer.String())
		})
	}
}
