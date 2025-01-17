package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

type AuthProvider struct {
	client HTTPClient
	store  cachestore.Store[jwk.Key]
}

func NewAuthProvider(cacheBackend cachestore.Backend, client HTTPClient) (auth.Provider, error) {
	if client == nil {
		client = http.DefaultClient
	}
	store, err := cachestorectl.Open[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	return &AuthProvider{
		client: client,
		store:  store,
	}, nil
}

func (p *AuthProvider) InitiateAuth(
	ctx context.Context,
	commitment *proto.AuthCommitmentData,
	ecosystemID string,
	verifier string,
	authKey *proto.AuthKey,
	storeFn auth.StoreCommitmentFn,
) (*proto.InitiateAuthResponse, error) {
	if commitment != nil {
		return nil, fmt.Errorf("cannot reuse an old ID token")
	}

	commitment, err := p.constructCommitment(proto.IdentityType_OIDC, ecosystemID, authKey, verifier)
	if err != nil {
		return nil, err
	}
	if err := storeFn(ctx, commitment); err != nil {
		return nil, err
	}

	res := &proto.InitiateAuthResponse{
		EcosystemID:  commitment.EcosystemID,
		AuthKey:      commitment.AuthKey,
		IdentityType: commitment.IdentityType,
		Verifier:     commitment.Verifier,
	}
	return res, nil
}

func (p *AuthProvider) Verify(ctx context.Context, commitment *proto.AuthCommitmentData, authKey *proto.AuthKey, answer string) (ident proto.Identity, err error) {
	if commitment == nil {
		return proto.Identity{}, fmt.Errorf("commitment not found")
	}

	tok, err := jwt.Parse([]byte(answer), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return proto.Identity{}, fmt.Errorf("parse JWT: %w", err)
	}

	issuer := normalizeIssuer(tok.Issuer())

	expectedHash := hexutil.Encode(ethcrypto.Keccak256([]byte(answer)))
	if commitment.Answer != expectedHash {
		return proto.Identity{}, fmt.Errorf("invalid token hash")
	}

	if err := p.verifyChallenge(tok, commitment.Challenge); err != nil {
		return proto.Identity{}, fmt.Errorf("verify challenge: %w", err)
	}

	ks := &operationKeySet{
		ctx:       ctx,
		iss:       issuer,
		store:     p.store,
		getKeySet: p.GetKeySet,
	}

	if _, err := jws.Verify([]byte(answer), jws.WithKeySet(ks, jws.WithMultipleKeysPerKeyID(false))); err != nil {
		return proto.Identity{}, fmt.Errorf("signature verification: %w", err)
	}

	vi, err := p.extractVerifier(commitment.Verifier)
	if err != nil {
		return proto.Identity{}, fmt.Errorf("extract verifier: %w", err)
	}

	validateOptions := []jwt.ValidateOption{
		jwt.WithValidator(withIssuer(vi.issuer, true)),
		jwt.WithValidator(withAudience([]string{vi.audience})),
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

func (p *AuthProvider) GetKeySet(ctx context.Context, issuer string) (set jwk.Set, err error) {
	jwksURL, err := fetchJWKSURL(ctx, p.client, issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}

	keySet, err := jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(tracing.WrapClientWithContext(ctx, p.client)))
	if err != nil {
		return nil, fmt.Errorf("fetch issuer keys: %w", err)
	}
	return keySet, nil
}

func (p *AuthProvider) constructCommitment(
	identityType proto.IdentityType, ecosystemID string, authKey *proto.AuthKey, verifier string,
) (*proto.AuthCommitmentData, error) {
	vi, err := p.extractVerifier(verifier)
	if err != nil {
		return nil, err
	}

	if time.Now().After(vi.expiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	answer := vi.tokHash
	challenge := fmt.Sprintf("exp=%d", vi.expiresAt.Unix())

	verifCtx := &proto.AuthCommitmentData{
		EcosystemID:  ecosystemID,
		AuthKey:      authKey,
		IdentityType: identityType,
		Verifier:     verifier,
		Answer:       answer,
		Challenge:    challenge,
		Expiry:       vi.expiresAt,
	}
	return verifCtx, nil
}

type verifierInfo struct {
	issuer    string
	audience  string
	tokHash   string
	expiresAt time.Time
}

func (p *AuthProvider) extractVerifier(verifier string) (*verifierInfo, error) {
	parts := strings.SplitN(verifier, "|", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid verifier format")
	}

	issuer := parts[0]
	audience := parts[1]
	tokHash := parts[2]
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse exp: %w", err)
	}
	expiresAt := time.Unix(exp, 0)

	vi := &verifierInfo{
		issuer:    issuer,
		audience:  audience,
		tokHash:   tokHash,
		expiresAt: expiresAt,
	}
	return vi, nil
}

func (p *AuthProvider) verifyChallenge(tok jwt.Token, challenge string) error {
	s := strings.TrimPrefix(challenge, "exp=")
	exp, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("parse exp: %w", err)
	}
	expiresAt := time.Unix(exp, 0)

	if !tok.Expiration().Equal(expiresAt) {
		return fmt.Errorf("invalid exp claim")
	}

	return nil
}
