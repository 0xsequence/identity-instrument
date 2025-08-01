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
	"github.com/0xsequence/identity-instrument/auth/authcode"
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

		hashedToken := hexutil.Encode(crypto.Keccak256([]byte(tok)))

		protoAuthKey := &proto.Key{
			KeyType: proto.KeyType_Secp256k1,
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
			SignerType:   proto.KeyType_Secp256k1,
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

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)

		signParams := &proto.SignParams{
			Scope:  proto.Scope("@123"),
			Signer: *resSigner,
			Digest: digestHex,
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
		assert.Equal(t, "Secp256k1:"+strings.ToLower(addr.Hex()), resSigner.String())
	})

	t.Run("AuthMode_AuthCode", func(t *testing.T) {
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

		code := authServer.authorize(map[string]string{
			"client_id":    "audience",
			"redirect_uri": "http://localhost:8080/callback",
		})
		require.NotEmpty(t, code)

		codeHash := hexutil.Encode(crypto.Keccak256([]byte(code)))

		protoAuthKey := &proto.Key{
			KeyType: proto.KeyType_Secp256k1,
			Address: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
		}
		initiateParams := &proto.CommitVerifierParams{
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_AuthCode,
			IdentityType: proto.IdentityType_OIDC,
			Handle:       codeHash,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
			},
		}
		sig := signRequest(t, authKey, initiateParams)
		resVerifier, loginHint, challenge, err := c.CommitVerifier(ctx, initiateParams, protoAuthKey, sig)
		require.NoError(t, err)
		require.NotEmpty(t, resVerifier)
		require.Empty(t, challenge)
		require.Empty(t, loginHint)

		registerParams := &proto.CompleteAuthParams{
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_AuthCode,
			IdentityType: proto.IdentityType_OIDC,
			SignerType:   proto.KeyType_Secp256k1,
			Verifier:     resVerifier,
			Answer:       code,
		}
		sig = signRequest(t, authKey, registerParams)
		resSigner, resIdentity, err := c.CompleteAuth(ctx, registerParams, protoAuthKey, sig)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)
		require.NotEmpty(t, resIdentity)
		assert.Equal(t, resIdentity.Type, proto.IdentityType_OIDC)
		assert.Equal(t, resIdentity.Subject, "subject")
		assert.Equal(t, resIdentity.Issuer, issuer)

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)

		signParams := &proto.SignParams{
			Scope:  proto.Scope("@123"),
			Signer: *resSigner,
			Digest: digestHex,
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
		assert.Equal(t, "Secp256k1:"+strings.ToLower(addr.Hex()), resSigner.String())
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

		protoAuthKey := &proto.Key{
			KeyType: proto.KeyType_Secp256k1,
			Address: crypto.PubkeyToAddress(authKey.PublicKey).Hex(),
		}
		initiateParams := &proto.CommitVerifierParams{
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_AuthCodePKCE,
			IdentityType: proto.IdentityType_OIDC,
			Metadata: map[string]string{
				"iss": issuer,
				"aud": "audience",
			},
		}
		sig := signRequest(t, authKey, initiateParams)
		resVerifier, loginHint, challenge, err := c.CommitVerifier(ctx, initiateParams, protoAuthKey, sig)
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
			Scope:        proto.Scope("@123"),
			AuthMode:     proto.AuthMode_AuthCodePKCE,
			IdentityType: proto.IdentityType_OIDC,
			SignerType:   proto.KeyType_Secp256k1,
			Verifier:     resVerifier,
			Answer:       code,
		}
		sig = signRequest(t, authKey, registerParams)
		resSigner, resIdentity, err := c.CompleteAuth(ctx, registerParams, protoAuthKey, sig)
		require.NoError(t, err)
		require.NotEmpty(t, resSigner)
		require.NotEmpty(t, resIdentity)
		assert.Equal(t, resIdentity.Type, proto.IdentityType_OIDC)
		assert.Equal(t, resIdentity.Subject, "subject")
		assert.Equal(t, resIdentity.Issuer, issuer)

		digest := crypto.Keccak256([]byte("message"))
		digestHex := hexutil.Encode(digest)

		signParams := &proto.SignParams{
			Scope:  proto.Scope("@123"),
			Signer: *resSigner,
			Digest: digestHex,
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
		assert.Equal(t, "Secp256k1:"+strings.ToLower(addr.Hex()), resSigner.String())
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

	secretConfig := &authcode.SecretConfig{
		Value: &clientSecret,
	}
	secretConfigJSON, err := json.Marshal(secretConfig)
	require.NoError(t, err)

	secretName := "oauth/123/" + encodeValueForSecretName(s.URL()) + "/audience"
	_, err = svc.Secrets.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(string(secretConfigJSON)),
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
