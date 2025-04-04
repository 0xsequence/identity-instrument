package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	proto "github.com/0xsequence/identity-instrument/proto/clients"
	"github.com/0xsequence/identity-instrument/rpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDC(t *testing.T) {
	t.Run("AuthMode_IDToken", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		svc := initRPC(t, nil)

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
		header := make(http.Header)
		ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
		require.NoError(t, err)

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))

		initiateParams := &proto.CommitVerifierParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
			},
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			Handle:       hashedToken,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
				"exp": strconv.Itoa(int(exp.Unix())),
			},
		}
		resVerifier, loginHint, challenge, err := c.CommitVerifier(ctx, initiateParams)
		require.NoError(t, err)
		require.Equal(t, initiateParams.Handle, resVerifier)
		require.Empty(t, loginHint)
		require.Empty(t, challenge)

		registerParams := &proto.CompleteAuthParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
			},
			AuthMode:     proto.AuthMode_IDToken,
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     resVerifier,
			Answer:       tok,
		}
		resSigner, err := c.CompleteAuth(ctx, registerParams)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
		sig, err := crypto.Sign(prefixedHash, authKey)
		require.NoError(t, err)

		signParams := &proto.SignParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
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

	t.Run("AuthMode_AuthCodePKCE", func(t *testing.T) {
		ctx := context.Background()

		exp := time.Now().Add(120 * time.Second)
		tokBuilderFn := func(b *jwt.Builder, url string) {
			b.Expiration(exp)
		}

		svc := initRPC(t, nil)

		authServer := newMockOAuth2Server(t, svc)
		defer authServer.Close()
		authServer.tokenBuilderFn = tokBuilderFn

		issuer := authServer.URL()

		authKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		require.NoError(t, err)

		srv := httptest.NewServer(svc.Handler())
		defer srv.Close()

		c := proto.NewIdentityInstrumentClient(srv.URL, http.DefaultClient)
		header := make(http.Header)
		ctx, err = proto.WithHTTPRequestHeaders(ctx, header)
		require.NoError(t, err)

		initiateParams := &proto.CommitVerifierParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
			},
			AuthMode:     proto.AuthMode_AuthCodePKCE,
			IdentityType: proto.IdentityType_OIDC,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
			},
		}
		resVerifier, loginHint, challenge, err := c.CommitVerifier(ctx, initiateParams)
		require.NoError(t, err)
		require.NotEmpty(t, resVerifier)
		require.NotEmpty(t, challenge)
		require.Empty(t, loginHint)

		code := authServer.authorize(map[string]string{
			"client_id":             "audience",
			"redirect_uri":          "http://localhost:8080/callback",
			"code_challenge":        challenge,
			"code_challenge_method": "S256",
		})
		require.NotEmpty(t, code)

		registerParams := &proto.CompleteAuthParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
			},
			AuthMode:     proto.AuthMode_AuthCodePKCE,
			IdentityType: proto.IdentityType_OIDC,
			Verifier:     resVerifier,
			Answer:       code,
		}
		resSigner, err := c.CompleteAuth(ctx, registerParams)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
		sig, err := crypto.Sign(prefixedHash, authKey)
		require.NoError(t, err)

		signParams := &proto.SignParams{
			Ecosystem: "ECO_ID",
			AuthKey: &proto.AuthKey{
				KeyType:   proto.KeyType_P256K1,
				PublicKey: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
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

type mockOAuth2Server struct {
	t              *testing.T
	server         *httptest.Server
	codes          map[string]codeData
	jwtKey         jwk.Key
	tokenBuilderFn func(b *jwt.Builder, url string)
	clientSecret   string
}

type codeData struct {
	codeChallenge       string
	codeChallengeMethod string
	clientID            string
	redirectURI         string
}

func newMockOAuth2Server(t *testing.T, svc *rpc.RPC) *mockOAuth2Server {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	clientSecret := hexutil.Encode(secret)

	jwtKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtKey, err := jwk.FromRaw(jwtKeyRaw)
	require.NoError(t, err)
	require.NoError(t, jwtKey.Set(jwk.KeyIDKey, "key-id"))

	s := &mockOAuth2Server{
		t:            t,
		codes:        make(map[string]codeData),
		jwtKey:       jwtKey,
		clientSecret: clientSecret,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleOpenIDConfig)

	s.server = httptest.NewServer(mux)

	secretName := "oauth/ECO_ID/" + encodeValueForSecretName(s.URL()) + "/audience"
	_, err = svc.Secrets.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(clientSecret),
	})
	require.NoError(t, err)

	return s
}

func (s *mockOAuth2Server) URL() string {
	return s.server.URL
}

func (s *mockOAuth2Server) Close() {
	s.server.Close()
}

func (s *mockOAuth2Server) authorize(params map[string]string) string {
	// Validate required PKCE parameters
	codeChallenge := params["code_challenge"]
	codeChallengeMethod := params["code_challenge_method"]

	require.NotEmpty(s.t, codeChallenge)
	require.NotEmpty(s.t, codeChallengeMethod)

	// Generate authorization code
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	require.NoError(s.t, err)

	code := fmt.Sprintf("code-%x", randBytes)

	// Store code data
	s.codes[code] = codeData{
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		clientID:            params["client_id"],
		redirectURI:         params["redirect_uri"],
	}

	return code
}

func (s *mockOAuth2Server) handleToken(w http.ResponseWriter, r *http.Request) {
	require.NoError(s.t, r.ParseForm())

	code := r.Form.Get("code")
	codeVerifier := r.Form.Get("code_verifier")

	data, ok := s.codes[code]
	require.True(s.t, ok)

	delete(s.codes, code)

	// Verify PKCE code challenge
	if data.codeChallengeMethod == "S256" {
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		calculatedChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		require.Equal(s.t, calculatedChallenge, data.codeChallenge)
	}

	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	require.NoError(s.t, err)

	idToken := s.issueIDToken(data.clientID)

	// Return token response
	resp := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token,omitempty"`
	}{
		AccessToken: fmt.Sprintf("token-%x", randBytes),
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *mockOAuth2Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	m, err := s.jwtKey.AsMap(r.Context())
	require.NoError(s.t, err)
	m["alg"] = "RS256"
	pkd := map[string]any{"keys": []any{m}}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(pkd)
}

func (s *mockOAuth2Server) handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":         s.URL(),
		"jwks_uri":       s.URL() + "/jwks",
		"token_endpoint": s.URL() + "/token",
	})
}

func (s *mockOAuth2Server) issueIDToken(clientID string) string {
	tokBuilder := jwt.NewBuilder().
		Issuer(s.URL()).
		Audience([]string{clientID}).
		Subject("subject")

	if s.tokenBuilderFn != nil {
		s.tokenBuilderFn(tokBuilder, s.URL())
	}

	tokRaw, err := tokBuilder.Build()
	require.NoError(s.t, err)
	tokBytes, err := jwt.Sign(tokRaw, jwt.WithKey(jwa.RS256, s.jwtKey))
	require.NoError(s.t, err)
	return string(tokBytes)
}

func encodeValueForSecretName(value string) string {
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
	}

	var result strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' {
			result.WriteRune(char)
		} else {
			result.WriteRune('-')
		}
	}
	return result.String()
}
