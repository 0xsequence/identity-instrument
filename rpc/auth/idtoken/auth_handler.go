package idtoken

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/auth"
	"github.com/0xsequence/waas-authenticator/rpc/tracing"
	"github.com/goware/cachestore"
	"github.com/goware/cachestore/cachestorectl"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthHandler struct {
	client HTTPClient
	store  cachestore.Store[jwk.Key]
}

var _ auth.Handler = (*AuthHandler)(nil)

func NewAuthHandler(cacheBackend cachestore.Backend, client HTTPClient) (*AuthHandler, error) {
	if client == nil {
		client = http.DefaultClient
	}
	store, err := cachestorectl.Open[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	return &AuthHandler{
		client: client,
		store:  store,
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
) (resVerifier string, resChallenge string, err error) {
	if commitment != nil {
		return "", "", fmt.Errorf("cannot reuse an old ID token")
	}

	commitment, err = h.constructCommitment(authID, authKey, metadata)
	if err != nil {
		return "", "", err
	}
	if err := storeFn(ctx, commitment); err != nil {
		return "", "", err
	}

	return commitment.Verifier, commitment.Challenge, nil
}

func (h *AuthHandler) Verify(ctx context.Context, commitment *proto.AuthCommitmentData, authKey *proto.AuthKey, answer string) (proto.Identity, error) {
	if commitment == nil {
		return proto.Identity{}, fmt.Errorf("commitment not found")
	}

	expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
	if commitment.Verifier != expectedHash {
		return proto.Identity{}, fmt.Errorf("invalid token hash")
	}

	vi, err := h.extractMetadata(commitment.Metadata)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("extract metadata: %w", err)
	}

	return h.VerifyToken(ctx, answer, vi.issuer, vi.audience, h.getVerifyChallengeFunc(commitment))
}

func (h *AuthHandler) VerifyToken(
	ctx context.Context,
	idToken string,
	expectedIssuer string,
	expectedAudience string,
	verifyChallenge func(tok jwt.Token) error,
) (proto.Identity, error) {
	tok, err := jwt.Parse([]byte(idToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("parse JWT: %w", err)
	}

	if err := verifyChallenge(tok); err != nil {
		return proto.Identity{}, fmt.Errorf("verify challenge: %w", err)
	}

	issuer := normalizeIssuer(tok.Issuer())

	ks := &operationKeySet{
		ctx:       ctx,
		iss:       issuer,
		store:     h.store,
		getKeySet: h.GetKeySet,
	}

	if _, err := jws.Verify([]byte(idToken), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(expectedIssuer, true)),
		jwt.WithValidator(withAudience([]string{expectedAudience})),
		jwt.WithAcceptableSkew(10 * time.Second),
	}

	if err := jwt.Validate(tok, validateOptions...); err != nil {
		return proto.Identity{}, fmt.Errorf("JWT validation: %w", err)
	}

	identity := proto.Identity{
		Type:    proto.IdentityType_OIDC,
		Issuer:  issuer,
		Subject: tok.Subject(),
		Email:   getEmailFromToken(tok),
	}
	return identity, nil
}

func (h *AuthHandler) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
	jwksURL, err := fetchJWKSURL(ctx, h.client, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(tracing.WrapClientWithContext(ctx, h.client)))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
}

func (h *AuthHandler) constructCommitment(
	authID proto.AuthID, authKey *proto.AuthKey, metadata map[string]string,
) (*proto.AuthCommitmentData, error) {
	vi, err := h.extractMetadata(metadata)
	if err != nil {
		return nil, err
	}

	if time.Now().After(vi.expiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	commitment := &proto.AuthCommitmentData{
		Ecosystem:    authID.Ecosystem,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Verifier:     authID.Verifier,
		Expiry:       vi.expiresAt,
		Metadata:     metadata,
	}
	return commitment, nil
}

type verifierInfo struct {
	issuer    string
	audience  string
	expiresAt time.Time
}

func (h *AuthHandler) extractMetadata(metadata map[string]string) (*verifierInfo, error) {
	issuer := metadata["iss"]
	audience := metadata["aud"]
	exp, err := strconv.ParseInt(metadata["exp"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse exp: %w", err)
	}
	expiresAt := time.Unix(exp, 0)

	vi := &verifierInfo{
		issuer:    issuer,
		audience:  audience,
		expiresAt: expiresAt,
	}
	return vi, nil
}

func (h *AuthHandler) getVerifyChallengeFunc(commitment *proto.AuthCommitmentData) func(tok jwt.Token) error {
	return func(tok jwt.Token) error {
		vi, err := h.extractMetadata(commitment.Metadata)
		if err != nil {
			return fmt.Errorf("extract metadata: %w", err)
		}

		if !tok.Expiration().Equal(vi.expiresAt) {
			return fmt.Errorf("invalid exp claim")
		}

		return nil
	}
}
