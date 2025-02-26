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
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/attestation"
	"github.com/0xsequence/identity-instrument/rpc/auth"
	"github.com/0xsequence/identity-instrument/rpc/auth/idtoken"
)

type AuthHandler struct {
	client         idtoken.HTTPClient
	idTokenHandler *idtoken.AuthHandler
	secretProvider SecretProvider
}

var _ auth.Handler = (*AuthHandler)(nil)

func NewAuthHandler(client idtoken.HTTPClient, idTokenHandler *idtoken.AuthHandler, secretProvider SecretProvider) (auth.Handler, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if idTokenHandler == nil {
		return nil, fmt.Errorf("idtoken handler is nil")
	}
	return &AuthHandler{
		client:         client,
		idTokenHandler: idTokenHandler,
		secretProvider: secretProvider,
	}, nil
}

func (*AuthHandler) Supports(identityType proto.IdentityType) bool {
	return identityType == proto.IdentityType_OIDC
}

func (h *AuthHandler) Commit(
	ctx context.Context,
	authID proto.AuthID,
	commitment *proto.AuthCommitmentData,
	authKey *proto.AuthKey,
	metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (resVerifier string, challenge string, err error) {
	att := attestation.FromContext(ctx)

	if commitment != nil {
		return "", "", fmt.Errorf("cannot reuse an old commitment")
	}

	codeVerifier, err := randomHex(att, 32)
	if err != nil {
		return "", "", fmt.Errorf("generate code verifier: %w", err)
	}
	codeVerifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.EncodeToString(codeVerifierHash[:])

	commitment = &proto.AuthCommitmentData{
		Ecosystem:    authID.Ecosystem,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Verifier:     codeChallenge,
		Answer:       codeVerifier,
		Challenge:    codeChallenge,
		Metadata:     metadata,
		Expiry:       time.Now().Add(5 * time.Minute),
	}
	if err := storeFn(ctx, commitment); err != nil {
		return "", "", err
	}

	return commitment.Verifier, commitment.Challenge, nil
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

	clientSecret, err := h.secretProvider.GetClientSecret(ctx, commitment.Ecosystem, iss, aud)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("get client secret: %w", err)
	}

	// TODO: get these from the oidc configuration:
	// - token endpoint
	// - whether to use basic auth or client_id/client_secret
	tokenEndpoint := "https://oauth2.googleapis.com/token"
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

	if resp.StatusCode != http.StatusOK {
		return proto.Identity{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return proto.Identity{}, fmt.Errorf("decode response: %w", err)
	}

	if err, ok := body["error"]; ok {
		return proto.Identity{}, fmt.Errorf("oauth error: %s", err)
	}

	idToken := body["id_token"].(string)

	return h.idTokenHandler.VerifyToken(ctx, idToken, iss, aud, nil)
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}
