package rpc_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	proto "github.com/0xsequence/identity-instrument/proto/clients"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	t.Run("IdentityType_OIDC", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		issuer, tok, closeJWKS := issueAccessTokenAndRunJwksServer(t, tokBuilderFn)
		defer closeJWKS()

		authKey, err := ethwallet.NewWalletFromRandomEntropy()
		require.NoError(t, err)

		svc := initRPC(t, nil)

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewIdentityInstrumentClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
		require.NoError(t, err)

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))

		initiateParams := &proto.InitiateAuthParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.Address().Hex(),
			},
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     hashedToken,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
				"exp": strconv.Itoa(int(exp.Unix())),
			},
		}
		resVerifier, challenge, err := c.InitiateAuth(ctx, initiateParams)
		require.NoError(t, err)
		require.Equal(t, initiateParams.Verifier, resVerifier)
		require.Empty(t, challenge)

		registerParams := &proto.RegisterAuthParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.Address().Hex(),
			},
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     resVerifier,
			Answer:       tok,
		}
		resSigner, err := c.RegisterAuth(ctx, registerParams)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
		sig, err := crypto.Sign(prefixedHash, authKey.PrivateKey())
		require.NoError(t, err)

		signParams := &proto.SignParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.Address().Hex(),
			},
			Signer:    resSigner,
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
		assert.Equal(t, addr.String(), resSigner)
	})
}
