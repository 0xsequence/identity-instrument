package authcode

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/goware/cachestore"
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
	client idtoken.HTTPClient,
	idTokenHandler *idtoken.AuthHandler,
	secretProvider SecretProvider,
	randomProvider func(ctx context.Context) io.Reader,
	secretStore cachestore.Store[string],
) (auth.Handler, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if idTokenHandler == nil {
		return nil, fmt.Errorf("idtoken handler is nil")
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
	authKey proto.Key,
	metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (resVerifier string, loginHint string, challenge string, err error) {
	log := o11y.LoggerFromContext(ctx)

	if _, err := ExtractMetadata(metadata); err != nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("extract metadata: %w", err)
	}

	commitment := &proto.AuthCommitmentData{
		Scope:        authID.Scope,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Metadata:     metadata,
		// We don't know what the validity of the auth code itself is. So we set this to a long time
		// to prevent replays, as the hash of the code identifies the commitment.
		Expiry: time.Now().Add(365 * 24 * time.Hour),
	}

	if commitment.AuthMode == proto.AuthMode_AuthCodePKCE {
		codeVerifier, err := randomHex(h.randomProvider(ctx), 32)
		if err != nil {
			log.Error("failed to generate code verifier", "error", err)
			return "", "", "", proto.ErrInternalError
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
		commitment.Signer, err = signer.Key()
		if err != nil {
			log.Error("failed to get signer address", "error", err)
			return "", "", "", proto.ErrDataIntegrityError
		}
	}

	if err := storeFn(ctx, commitment); err != nil {
		log.Error("failed to store commitment", "error", err)
		return "", "", "", err
	}

	return commitment.Verifier(), loginHint, commitment.Challenge, nil
}

func (h *AuthHandler) Verify(
	ctx context.Context,
	commitment *proto.AuthCommitmentData,
	authKey proto.Key,
	answer string,
) (proto.Identity, error) {
	log := o11y.LoggerFromContext(ctx)

	if commitment == nil {
		log.Error("commitment not found")
		return proto.Identity{}, proto.ErrInvalidRequest.WithCausef("commitment not found")
	}

	// When not in PKCE mode, we need to verify that the hashed answer matches the commitment
	if commitment.AuthMode != proto.AuthMode_AuthCodePKCE {
		expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
		if commitment.Handle != expectedHash {
			log.Error("invalid token hash", "expected", expectedHash, "actual", commitment.Handle)
			return proto.Identity{}, proto.ErrProofVerificationFailed.WithCausef("invalid token hash")
		}
	}

	// The metadata should have been validated at this point
	m, err := ExtractMetadata(commitment.Metadata)
	if err != nil {
		log.Error("failed to extract metadata", "error", err)
		return proto.Identity{}, proto.ErrInternalError
	}

	clientSecret, err := h.GetClientSecret(ctx, commitment.Scope, m.Issuer, m.Audience)
	if err != nil {
		log.Error("failed to get client secret", "issuer", m.Issuer, "audience", m.Audience, "error", err)
		return proto.Identity{}, proto.ErrDatabaseError
	}

	openidConfig, err := h.idTokenHandler.GetOpenIDConfig(ctx, m.Issuer)
	if err != nil {
		log.Error("failed to get openid configuration", "issuer", m.Issuer, "error", err)
		return proto.Identity{}, proto.ErrIdentityProviderError
	}

	tokenEndpoint := openidConfig.TokenEndpoint
	if tokenEndpoint == "" {
		log.Error("token endpoint not found in openid configuration", "issuer", m.Issuer)
		return proto.Identity{}, proto.ErrIdentityProviderError
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", answer)
	data.Set("redirect_uri", m.RedirectURI)
	data.Set("client_id", m.Audience)
	data.Set("client_secret", clientSecret)
	if commitment.AuthMode == proto.AuthMode_AuthCodePKCE {
		data.Set("code_verifier", commitment.Answer)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		log.Error("failed to create request", "error", err)
		return proto.Identity{}, proto.ErrInternalError
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(req)
	if err != nil {
		log.Error("failed to do request", "error", err)
		return proto.Identity{}, proto.ErrIdentityProviderError
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Error("failed to decode response", "error", err)
		return proto.Identity{}, proto.ErrIdentityProviderError
	}

	if err, ok := body["error"]; ok {
		log.Error("token exchange oauth error", "error", err, "description", body["error_description"])
		return proto.Identity{}, proto.ErrOAuthError.WithCausef("%s: %s", err, body["error_description"])
	}

	if resp.StatusCode != http.StatusOK {
		log.Error("token exchange unexpected status code", "status", resp.StatusCode)
		return proto.Identity{}, proto.ErrIdentityProviderError
	}

	idToken := body["id_token"].(string)

	return h.idTokenHandler.VerifyToken(ctx, idToken, m.Issuer, m.Audience, nil)
}

func (h *AuthHandler) GetClientSecret(ctx context.Context, scope proto.Scope, iss string, aud string) (string, error) {
	ttl := 1 * time.Hour
	getter := func(ctx context.Context, _ string) (string, error) {
		return h.secretProvider.GetClientSecret(ctx, scope, iss, aud)
	}

	secretName := scope.String() + "|" + iss + "|" + aud
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

	rawKey, err := x509.ParsePKCS8PrivateKey(config.SigningKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	jwtKey, err := jwk.FromRaw(rawKey)
	if err != nil {
		return "", fmt.Errorf("convert to jwk: %w", err)
	}
	if err := jwtKey.Set(jwk.KeyIDKey, config.SigningKey.KeyID); err != nil {
		return "", fmt.Errorf("set key id: %w", err)
	}

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
