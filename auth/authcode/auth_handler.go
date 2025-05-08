package authcode

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/auth/idtoken"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/goware/cachestore"
	"github.com/goware/cachestore/memlru"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthHandler struct {
	client         idtoken.HTTPClient
	idTokenHandler *idtoken.AuthHandler
	secretStore    cachestore.Store[string]
	secretProvider SecretProvider
	randomProvider func(ctx context.Context) io.Reader
}

var _ auth.Handler = (*AuthHandler)(nil)

func NewAuthHandler(
	cacheBackend cachestore.Backend,
	client idtoken.HTTPClient,
	idTokenHandler *idtoken.AuthHandler,
	secretProvider SecretProvider,
	randomProvider func(ctx context.Context) io.Reader,
) (auth.Handler, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if idTokenHandler == nil {
		return nil, fmt.Errorf("idtoken handler is nil")
	}
	secretStore, err := memlru.NewWithBackend[string](cacheBackend)
	if err != nil {
		return nil, fmt.Errorf("open secret store: %w", err)
	}
	return &AuthHandler{
		client:         client,
		idTokenHandler: idTokenHandler,
		secretStore:    secretStore,
		secretProvider: secretProvider,
		randomProvider: randomProvider,
	}, nil
}

func (*AuthHandler) Supports(identityType proto.IdentityType) bool {
	return identityType == proto.IdentityType_OIDC
}

func (h *AuthHandler) Commit(
	ctx context.Context,
	authID proto.AuthID,
	_commitment *proto.AuthCommitmentData,
	signer *proto.SignerData,
	authKey *proto.AuthKey,
	metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (resVerifier string, loginHint string, challenge string, err error) {
	commitment := &proto.AuthCommitmentData{
		Ecosystem:    authID.Ecosystem,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Metadata:     metadata,
		Expiry:       time.Now().Add(5 * time.Minute),
	}

	if commitment.AuthMode == proto.AuthMode_AuthCodePKCE {
		codeVerifier, err := randomHex(h.randomProvider(ctx), 32)
		if err != nil {
			return "", "", "", proto.ErrInternalError.WithCausef("generate code verifier: %w", err)
		}
		codeVerifierHash := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(codeVerifierHash[:])

		commitment.Handle = codeChallenge
		commitment.Answer = codeVerifier
		commitment.Challenge = codeChallenge
	} else {
		// TODO verify that the verifier is a valid keccak256 hash
		commitment.Handle = authID.Verifier
	}

	if signer != nil {
		loginHint = signer.Identity.Subject
		commitment.Signer, err = signer.Address()
		if err != nil {
			return "", "", "", proto.ErrDataIntegrityError.WithCausef("failed to get signer address: %w", err)
		}
	}

	if err := storeFn(ctx, commitment); err != nil {
		return "", "", "", err
	}

	return commitment.Verifier(), loginHint, commitment.Challenge, nil
}

func (h *AuthHandler) Verify(
	ctx context.Context,
	commitment *proto.AuthCommitmentData,
	authKey *proto.AuthKey,
	answer string,
) (proto.Identity, error) {
	if commitment == nil {
		return proto.Identity{}, proto.ErrInvalidRequest.WithCausef("commitment not found")
	}

	// When not in PKCE mode, we need to verify that the hashed answer matches the commitment
	if commitment.AuthMode != proto.AuthMode_AuthCodePKCE {
		expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
		if commitment.Handle != expectedHash {
			return proto.Identity{}, proto.ErrProofVerificationFailed.WithCausef("invalid token hash")
		}
	}

	iss := commitment.Metadata["iss"]
	aud := commitment.Metadata["aud"]

	clientSecret, err := h.GetClientSecret(ctx, commitment.Ecosystem, iss, aud)
	if err != nil {
		return proto.Identity{}, proto.ErrDatabaseError.WithCausef("get client secret: %w", err)
	}

	openidConfig, err := h.idTokenHandler.GetOpenIDConfig(ctx, iss)
	if err != nil {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("get openid config: %w", err)
	}

	tokenEndpoint := openidConfig.TokenEndpoint
	if tokenEndpoint == "" {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("token endpoint not found in openid configuration")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", answer)
	data.Set("redirect_uri", commitment.Metadata["redirect_uri"])
	data.Set("client_id", aud)
	data.Set("client_secret", clientSecret)
	if commitment.AuthMode == proto.AuthMode_AuthCodePKCE {
		data.Set("code_verifier", commitment.Answer)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return proto.Identity{}, proto.ErrInternalError.WithCausef("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(req)
	if err != nil {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("do request: %w", err)
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("decode response: %w", err)
	}

	if err, ok := body["error"]; ok {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("oauth error: %s: %s", err, body["error_description"])
	}

	if resp.StatusCode != http.StatusOK {
		return proto.Identity{}, proto.ErrIdentityProviderError.WithCausef("unexpected status code: %d", resp.StatusCode)
	}

	idToken := body["id_token"].(string)

	return h.idTokenHandler.VerifyToken(ctx, idToken, iss, aud, nil)
}

func (h *AuthHandler) GetClientSecret(ctx context.Context, ecosystem string, iss string, aud string) (string, error) {
	ttl := 1 * time.Hour
	getter := func(ctx context.Context, _ string) (string, error) {
		return h.secretProvider.GetClientSecret(ctx, ecosystem, iss, aud)
	}

	secretName := ecosystem + "|" + iss + "|" + aud
	secretConfigString, err := h.secretStore.GetOrSetWithLockEx(ctx, secretName, getter, ttl)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}

	var secretConfig SecretConfig
	if err := json.Unmarshal([]byte(secretConfigString), &secretConfig); err != nil {
		return "", fmt.Errorf("unmarshal secret config: %w", err)
	}

	if secretConfig.Value != nil {
		return *secretConfig.Value, nil
	}

	if secretConfig.GenerateJWT != nil {
		return generateClientSecretJWT(secretConfig.GenerateJWT)
	}

	return "", nil
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}

func generateClientSecretJWT(config *GenerateJWT) (string, error) {
	builder := jwt.NewBuilder().
		Issuer(config.Claims.Issuer).
		Audience([]string{config.Claims.Audience}).
		Subject(config.Claims.Subject).
		Expiration(time.Now().Add(5 * time.Minute))

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	block, _ := pem.Decode([]byte(config.SigningKey.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("invalid private key")
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	jwtKey, err := jwk.FromRaw(rawKey)
	if err != nil {
		return "", fmt.Errorf("convert to jwk: %w", err)
	}
	jwtKey.Set(jwk.KeyIDKey, config.SigningKey.KeyID)

	var alg jwa.SignatureAlgorithm
	switch config.SigningKey.Algorithm {
	case "ES256":
		alg = jwa.ES256
	case "RS256":
		alg = jwa.RS256
	default:
		return "", fmt.Errorf("unsupported signing key algorithm: %s", config.SigningKey.Algorithm)
	}

	signedToken, err := jwt.Sign(token, jwt.WithKey(alg, jwtKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}
