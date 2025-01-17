package rpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	proto "github.com/0xsequence/identity-instrument/proto/clients"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	t.Run("OIDC", func(t *testing.T) {
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
		verifier := []string{
			issuer,
			"audience",
			hashedToken,
			strconv.Itoa(int(exp.Unix())),
		}

		initiateParams := &proto.InitiateAuthParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.PublicKeyHex(),
			},
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     strings.Join(verifier, "|"),
		}
		initiateRes, err := c.InitiateAuth(ctx, initiateParams)
		require.NoError(t, err)
		require.NotEmpty(t, initiateRes)

		registerParams := &proto.RegisterAuthParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.PublicKeyHex(),
			},
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     strings.Join(verifier, "|"),
			Answer:       tok,
		}
		registerRes, err := c.RegisterAuth(ctx, registerParams)
		require.NoError(t, err)
		require.NotEmpty(t, registerRes)

		digest := crypto.Keccak256([]byte("message"))
		sig, err := ethcrypto.Sign(digest, authKey.PrivateKey())
		require.NoError(t, err)

		signParams := &proto.SignParams{
			EcosystemID: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: authKey.PublicKeyHex(),
			},
			Signer:    registerRes.Signer,
			Digest:    hexutil.Encode(digest),
			Signature: hexutil.Encode(sig),
		}
		signRes, err := c.Sign(ctx, signParams)
		require.NoError(t, err)

		pub, err := ethcrypto.Ecrecover(digest, common.FromHex(signRes.Signature))
		require.NoError(t, err)
		addr := common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
		assert.Equal(t, addr.String(), registerRes.Signer)
	})
}
