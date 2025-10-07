package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/config"
	proto "github.com/0xsequence/identity-instrument/proto/clients"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsageLimits(t *testing.T) {
	ep, terminate := initLocalstack()
	defer terminate()

	t.Run("AuthKey", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				// skip TLS verification for testing
				InsecureSkipVerify: true,
			},
		}
		svc := initRPC(t, ep, transport, func(cfg *config.Config) {
			cfg.RateLimit.Enabled = true
			cfg.RateLimit.UsageLimit = 10
			cfg.RateLimit.WindowSize = 1 * time.Minute
		})

		authServer := newMockOAuth2Server(t, svc)
		defer authServer.Close()
		authServer.tokenBuilderFn = tokBuilderFn

		issuer := authServer.URL()
		tok := authServer.issueIDToken("audience")

		authKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(t, err)

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewIdentityInstrumentClient(srv.URL, http.DefaultClient)

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))

		protoAuthKey := &proto.Key{
			KeyType: proto.KeyType_Ethereum_Secp256k1,
			Address: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
		}
		initiateParams := &proto.CommitVerifierParams{
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			Handle:       hashedToken,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
				"exp": strconv.Itoa(int(exp.Unix())),
			},
		}
		sig := signRequest(t, authKey, initiateParams)
		resVerifier, loginHint, challenge, err := c.CommitVerifier(ctx, initiateParams, protoAuthKey, sig)
		require.NoError(t, err)
		require.Equal(t, initiateParams.Handle, resVerifier)
		require.Empty(t, loginHint)
		require.Empty(t, challenge)

		registerParams := &proto.CompleteAuthParams{
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			SignerType:   proto.KeyType_Ethereum_Secp256k1,
			Verifier:     resVerifier,
			Answer:       tok,
		}
		sig = signRequest(t, authKey, registerParams)
		resSigner, resIdentity, err := c.CompleteAuth(ctx, registerParams, protoAuthKey, sig)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)
		require.NotEmpty(t, resIdentity)
		assert.Equal(t, resIdentity.Type, proto.IdentityType_OIDC)
		assert.Equal(t, resIdentity.Subject, "subject")
		assert.Equal(t, resIdentity.Issuer, issuer)

		for i := 0; i < 10; i++ {
			digest := crypto.Keccak256([]byte("message" + strconv.Itoa(i)))
			digestHex := hexutil.Encode(digest)

			signParams := &proto.SignParams{
				Scope:  proto.Scope("@123"),
				Signer: *resSigner,
				Digest: digestHex,
			}
			sig = signRequest(t, authKey, signParams)
			_, err := c.Sign(ctx, signParams, protoAuthKey, sig)
			require.NoError(t, err)
		}

		digest := crypto.Keccak256([]byte("message over limit"))
		digestHex := hexutil.Encode(digest)

		signParams := &proto.SignParams{
			Scope:  proto.Scope("@123"),
			Signer: *resSigner,
			Digest: digestHex,
		}
		sig = signRequest(t, authKey, signParams)
		_, err = c.Sign(ctx, signParams, protoAuthKey, sig)
		require.Error(t, err)
		require.Equal(t, proto.ErrUsageLimitExceeded, err)
	})
}
