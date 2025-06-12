package idtoken

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/goware/cachestore"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthHandler struct {
	client            HTTPClient
	jwkStore          cachestore.Store[jwk.Key]
	openidConfigStore cachestore.Store[OpenIDConfig]
}

var _ auth.Handler = (*AuthHandler)(nil)

func NewAuthHandler(
	client HTTPClient,
	jwkStore cachestore.Store[jwk.Key],
	openidConfigStore cachestore.Store[OpenIDConfig],
) *AuthHandler {
	if client == nil {
		client = http.DefaultClient
	}

	return &AuthHandler{
		client:            client,
		jwkStore:          jwkStore,
		openidConfigStore: openidConfigStore,
	}
}

func (*AuthHandler) Supports(identityType proto.IdentityType) bool {
	return identityType == proto.IdentityType_OIDC
}

func (h *AuthHandler) Commit(
	ctx context.Context,
	authID proto.AuthID,
	commitment *proto.AuthCommitmentData,
	signer *proto.SignerData,
	authKey proto.Key,
	metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (resVerifier string, loginHint string, resChallenge string, err error) {
	if commitment != nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("cannot reuse an old ID token")
	}

	commitment, err = h.constructCommitment(authID, authKey, metadata)
	if err != nil {
		return "", "", "", err
	}
	if err := storeFn(ctx, commitment); err != nil {
		return "", "", "", err
	}

	return commitment.Handle, "", commitment.Challenge, nil
}

func (h *AuthHandler) Verify(
	ctx context.Context,
	commitment *proto.AuthCommitmentData,
	authKey proto.Key,
	answer string,
) (proto.Identity, error) {
	log := o11y.LoggerFromContext(ctx)

	if commitment == nil {
		return proto.Identity{}, proto.ErrInvalidRequest.WithCausef("commitment not found")
	}

	expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
	if commitment.Handle != expectedHash {
		log.Error("invalid token hash", "expected", expectedHash, "actual", commitment.Handle)
		return proto.Identity{}, proto.ErrProofVerificationFailed
	}

	vi, err := h.extractMetadata(commitment.Metadata)
	if err != nil {
		log.Error("failed to extract metadata", "error", err)
		return proto.Identity{}, proto.ErrProofVerificationFailed
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
	log := o11y.LoggerFromContext(ctx)
	tok, err := jwt.Parse([]byte(idToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Error("failed to parse JWT", "error", err)
		return proto.Identity{}, proto.ErrProofVerificationFailed
	}

	if verifyChallenge != nil {
		if err := verifyChallenge(tok); err != nil {
			log.Error("failed to verify challenge", "error", err)
			return proto.Identity{}, proto.ErrProofVerificationFailed
		}
	}

	issuer := normalizeIssuer(tok.Issuer())

	ks := &operationKeySet{
		ctx:       ctx,
		iss:       issuer,
		store:     h.jwkStore,
		getKeySet: h.GetKeySet,
	}

	if _, err := jws.Verify([]byte(idToken), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		log.Error("failed to verify signature", "error", err)
		return proto.Identity{}, proto.ErrProofVerificationFailed
	}

	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(expectedIssuer, true)),
		jwt.WithValidator(withAudience([]string{expectedAudience})),
		jwt.WithAcceptableSkew(10 * time.Second),
	}

	if err := jwt.Validate(tok, validateOptions...); err != nil {
		log.Error("failed to validate JWT", "error", err)
		return proto.Identity{}, proto.ErrProofVerificationFailed
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
	log := o11y.LoggerFromContext(ctx)
	openidConfig, err := h.GetOpenIDConfig(ctx, issuer)
	if err != nil {
		log.Error("failed to get openid configuration", "error", err)
		return nil, proto.ErrIdentityProviderError
	}

	jwksURL := openidConfig.JWKSURL
	if jwksURL == "" {
		log.Error("jwks_uri not found in openid configuration")
		return nil, proto.ErrIdentityProviderError
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(h.client))
	if err != nil {
		log.Error("failed to fetch issuer keys", "error", err)
		return nil, proto.ErrIdentityProviderError
	}
	return keySet, nil
}

func (h *AuthHandler) constructCommitment(
	authID proto.AuthID, authKey proto.Key, metadata map[string]string,
) (*proto.AuthCommitmentData, error) {
	vi, err := h.extractMetadata(metadata)
	if err != nil {
		return nil, err
	}

	if time.Now().After(vi.expiresAt) {
		return nil, proto.ErrProofVerificationFailed.WithCausef("token expired")
	}

	commitment := &proto.AuthCommitmentData{
		Scope:        authID.Scope,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Handle:       authID.Verifier,
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
