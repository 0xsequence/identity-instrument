package authcode

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/auth/idtoken"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/goware/cachestore"
	"github.com/goware/cachestore/memlru"
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
	codeVerifier, err := randomHex(h.randomProvider(ctx), 32)
	if err != nil {
		return "", "", "", fmt.Errorf("generate code verifier: %w", err)
	}
	codeVerifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeVerifierHash[:])

	commitment := &proto.AuthCommitmentData{
		Ecosystem:    authID.Ecosystem,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Handle:       codeChallenge,
		Answer:       codeVerifier,
		Challenge:    codeChallenge,
		Metadata:     metadata,
		Expiry:       time.Now().Add(5 * time.Minute),
	}

	if signer != nil {
		loginHint = signer.Identity.Subject
		commitment.Signer, err = signer.Address()
		if err != nil {
			return "", "", "", fmt.Errorf("failed to get signer address: %w", err)
		}
	}

	if err := storeFn(ctx, commitment); err != nil {
		return "", "", "", fmt.Errorf("store commitment: %w", err)
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
		return proto.Identity{}, fmt.Errorf("commitment not found")
	}

	iss := commitment.Metadata["iss"]
	aud := commitment.Metadata["aud"]

	clientSecret, err := h.GetClientSecret(ctx, commitment.Ecosystem, iss, aud)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("get client secret: %w", err)
	}

	openidConfig, err := h.idTokenHandler.GetOpenIDConfig(ctx, iss)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("get openid config: %w", err)
	}

	tokenEndpoint := openidConfig.TokenEndpoint
	if tokenEndpoint == "" {
		return proto.Identity{}, fmt.Errorf("token endpoint not found in openid configuration")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", answer)
	data.Set("redirect_uri", commitment.Metadata["redirect_uri"])
	data.Set("client_id", aud)
	data.Set("client_secret", clientSecret)
	data.Set("code_verifier", commitment.Answer) // TODO: only use PKCE if in AuthCodePKCE mode

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(req)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return proto.Identity{}, fmt.Errorf("decode response: %w", err)
	}

	if err, ok := body["error"]; ok {
		return proto.Identity{}, fmt.Errorf("oauth error: %s: %s", err, body["error_description"])
	}

	if resp.StatusCode != http.StatusOK {
		return proto.Identity{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
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
	secret, err := h.secretStore.GetOrSetWithLockEx(ctx, secretName, getter, ttl)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}
	return secret, nil
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}
