package rpc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/auth/authcode"
	"github.com/0xsequence/identity-instrument/auth/idtoken"
	"github.com/0xsequence/identity-instrument/auth/otp"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/proto/builder"
	"github.com/0xsequence/identity-instrument/rpc/email"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goware/cachestore/memlru"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func (s *RPC) CommitVerifier(ctx context.Context, params *proto.CommitVerifierParams, authKey *proto.Key, signature string) (string, string, string, error) {
	att := attestation.FromContext(ctx)
	log := o11y.LoggerFromContext(ctx)

	scope, err := s.getScope(ctx, params)
	if err != nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("valid scope is required")
	}
	if err := params.Validate(); err != nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("invalid params: %w", err)
	}

	authHandler, err := s.getAuthHandler(params.AuthMode)
	if err != nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("get auth handler: %w", err)
	}

	if !authHandler.Supports(params.IdentityType) {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("unsupported identity type: %v", params.IdentityType)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		Scope:        scope,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Handle,
	}

	var signer *proto.SignerData
	if params.Signer.IsValid() {
		authID.Verifier = params.Signer.String()
		dbSigner, found, err := s.Signers.GetByAddress(ctx, scope, *params.Signer)
		if err != nil {
			log.Error("retrieve signer by address failed", "error", err)
			return "", "", "", proto.ErrDatabaseError
		}
		if !found {
			return "", "", "", proto.ErrInvalidRequest.WithCausef("signer not found")
		}
		signer, err = dbSigner.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
		if err != nil {
			log.Error("decrypt signer data failed", "error", err)
			return "", "", "", proto.ErrEncryptionError
		}
		if signer.Identity.Type != params.IdentityType {
			log.Error("signer identity type mismatch", "expected_identity_type", signer.Identity.Type, "params_identity_type", params.IdentityType)
			return "", "", "", proto.ErrDataIntegrityError
		}
	}

	if authID.Verifier != "" {
		dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
		if err != nil {
			log.Error("retrieve auth commitment failed", "error", err)
			return "", "", "", proto.ErrDatabaseError
		}
		if found && dbCommitment != nil {
			commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
			if err != nil {
				log.Error("decrypt auth commitment failed", "error", err)
				return "", "", "", proto.ErrEncryptionError
			}
		}
	}

	storeFn := func(ctx context.Context, commitment *proto.AuthCommitmentData) error {
		encryptedData, err := data.Encrypt(ctx, att, s.EncryptionPool, commitment)
		if err != nil {
			log.Error("encrypt auth commitment failed", "error", err)
			return proto.ErrEncryptionError
		}

		dbCommitment := &data.AuthCommitment{
			AuthID: &proto.AuthID{
				Scope:        commitment.Scope,
				AuthMode:     commitment.AuthMode,
				IdentityType: commitment.IdentityType,
				Verifier:     commitment.Verifier(),
			},
			ExpiresAt:     commitment.Expiry,
			EncryptedData: encryptedData,
		}

		if !dbCommitment.CorrespondsTo(commitment) {
			log.Error("invalid commitment", "commitment", commitment)
			return proto.ErrDataIntegrityError
		}

		if err := s.AuthCommitments.Put(ctx, dbCommitment); err != nil {
			log.Error("put auth commitment failed", "error", err)
			return proto.ErrDatabaseError
		}
		return nil
	}

	return authHandler.Commit(ctx, authID, commitment, signer, *authKey, params.Metadata, storeFn)
}

func (s *RPC) CompleteAuth(ctx context.Context, params *proto.CompleteAuthParams, authKey *proto.Key, signature string) (*proto.Key, *proto.Identity, error) {
	att := attestation.FromContext(ctx)
	log := o11y.LoggerFromContext(ctx)

	scope, err := s.getScope(ctx, params)
	if err != nil {
		return nil, nil, proto.ErrInvalidRequest.WithCausef("valid scope is required")
	}
	if err := params.Validate(); err != nil {
		return nil, nil, proto.ErrInvalidRequest.WithCausef("invalid params: %w", err)
	}

	// Currently we only support Ethereum_Secp256k1 signers
	if !params.SignerType.Is(proto.KeyType_Ethereum_Secp256k1) {
		return nil, nil, proto.ErrInvalidRequest.WithCausef("signer key type must be Ethereum_Secp256k1")
	}

	authHandler, err := s.getAuthHandler(params.AuthMode)
	if err != nil {
		return nil, nil, proto.ErrInvalidRequest.WithCausef("get auth handler: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		Scope:        scope,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		log.Error("retrieve auth commitment failed", "error", err)
		return nil, nil, proto.ErrDatabaseError
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
		if err != nil {
			log.Error("decrypt auth commitment failed", "error", err)
			return nil, nil, proto.ErrEncryptionError
		}

		if commitment.Attempts >= 3 {
			return nil, nil, proto.ErrTooManyAttempts
		}

		if time.Now().After(commitment.Expiry) {
			return nil, nil, proto.ErrChallengeExpired
		}

		if !dbCommitment.CorrespondsTo(commitment) || commitment.Scope != scope {
			log.Error("auth commitment mismatch", "commitment", commitment, "scope", scope)
			return nil, nil, proto.ErrDataIntegrityError
		}
	}

	ident, err := authHandler.Verify(ctx, commitment, *authKey, params.Answer)
	if err != nil {
		if commitment != nil {
			commitment.Attempts += 1
			encryptedData, err := data.Encrypt(ctx, att, s.EncryptionPool, commitment)
			if err != nil {
				log.Error("encrypt auth commitment failed", "error", err)
				return nil, nil, proto.ErrEncryptionError
			}
			if err := s.AuthCommitments.UpdateData(ctx, dbCommitment, encryptedData); err != nil {
				log.Error("update auth commitment failed", "error", err)
				return nil, nil, proto.ErrDatabaseError
			}
		}
		return nil, nil, err
	}

	// always use normalized email address
	ident.Email = email.Normalize(ident.Email)

	dbSigner, signerFound, err := s.Signers.GetByIdentity(ctx, ident, scope, params.SignerType)
	if err != nil {
		log.Error("retrieve signer failed", "error", err)
		return nil, nil, proto.ErrDatabaseError
	}

	if dbSigner != nil && commitment.Signer.IsValid() && !dbSigner.CorrespondsToProtoKey(commitment.Signer) {
		log.Error("signer address mismatch", "commitment_signer", commitment.Signer, "db_signer", dbSigner.Key())
		return nil, nil, proto.ErrDataIntegrityError
	}

	if !signerFound {
		if commitment.Signer.IsValid() {
			log.Error("signer not found", "commitment_signer", commitment.Signer)
			return nil, nil, proto.ErrDataIntegrityError
		}

		signer, err := ecdsa.GenerateKey(secp256k1.S256(), att)
		if err != nil {
			log.Error("generate signer failed", "error", err)
			return nil, nil, proto.ErrInternalError
		}

		signerData := &proto.SignerData{
			Scope:      scope,
			Identity:   &ident,
			KeyType:    params.SignerType,
			PrivateKey: hexutil.Encode(crypto.FromECDSA(signer)),
		}
		encData, err := data.Encrypt(ctx, att, s.EncryptionPool, signerData)
		if err != nil {
			log.Error("encrypt signer data failed", "error", err)
			return nil, nil, proto.ErrEncryptionError
		}
		dbSigner = &data.Signer{
			ScopedKeyType: data.ScopedKeyType{
				Scope:   scope,
				KeyType: params.SignerType,
			},
			Address:       strings.ToLower(crypto.PubkeyToAddress(signer.PublicKey).Hex()),
			Identity:      &ident,
			EncryptedData: encData,
		}
		if err := s.Signers.Put(ctx, dbSigner); err != nil {
			log.Error("put signer failed", "error", err)
			return nil, nil, proto.ErrDatabaseError
		}
	}

	maxTTL := 90 * 24 * time.Hour // 90 days
	ttl := 5 * time.Minute

	if params.Lifetime != nil {
		ttl = time.Duration(*params.Lifetime) * time.Second
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	authKeyData := &proto.AuthKeyData{
		Scope:   scope,
		Signer:  dbSigner.Key(),
		AuthKey: *authKey,
		Expiry:  time.Now().Add(ttl),
	}

	encData, err := data.Encrypt(ctx, att, s.EncryptionPool, authKeyData)
	if err != nil {
		log.Error("encrypt auth key data failed", "error", err)
		return nil, nil, proto.ErrEncryptionError
	}

	dbAuthKey := &data.AuthKey{
		Scope:         scope,
		Key:           authKey,
		ExpiresAt:     authKeyData.Expiry,
		EncryptedData: encData,
	}
	if err := s.AuthKeys.Put(ctx, dbAuthKey); err != nil {
		log.Error("put auth key failed", "error", err)
		return nil, nil, proto.ErrDatabaseError
	}

	res := dbSigner.Key()
	return &res, &ident, nil
}

func (s *RPC) getAuthHandler(authMode proto.AuthMode) (auth.Handler, error) {
	authHandler, ok := s.AuthHandlers[authMode]
	if !ok {
		return nil, fmt.Errorf("unknown auth mode: %v", authMode)
	}
	return authHandler, nil
}

func (s *RPC) makeAuthHandlers(awsCfg aws.Config, cfg config.Config) (map[proto.AuthMode]auth.Handler, error) {
	cacheBackend := memlru.Backend(1024)

	jwkStore, err := memlru.NewWithBackend[jwk.Key](cacheBackend)
	if err != nil {
		return nil, err
	}
	openidConfigStore, err := memlru.NewWithBackend[idtoken.OpenIDConfig](cacheBackend)
	if err != nil {
		return nil, err
	}
	idTokenHandler := idtoken.NewAuthHandler(
		s.HTTPClient,
		o11y.NewTracedCache("idtoken.jwkStore", jwkStore),
		o11y.NewTracedCache("idtoken.openidConfigStore", openidConfigStore),
	)

	secretStore, err := memlru.NewWithBackend[string](cacheBackend)
	if err != nil {
		return nil, err
	}
	randomProvider := func(ctx context.Context) io.Reader {
		return attestation.FromContext(ctx)
	}
	secretProvider := authcode.SecretProviderFunc(func(ctx context.Context, scope proto.Scope, iss string, aud string) (string, error) {
		ecosystem, err := scope.Ecosystem()
		if err != nil {
			return "", fmt.Errorf("get ecosystem: %w", err)
		}
		secretName := "oauth/" + ecosystem + "/" + encodeValueForSecretName(iss) + "/" + encodeValueForSecretName(aud)

		secret, err := s.Secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			return "", fmt.Errorf("get secret: %w", err)
		}
		if secret.SecretString == nil {
			return "", fmt.Errorf("secret is nil")
		}
		return *secret.SecretString, nil
	})
	authCodeHandler, err := authcode.NewAuthHandler(
		s.HTTPClient,
		idTokenHandler,
		secretProvider,
		randomProvider,
		o11y.NewTracedCache("authcode.secretStore", secretStore),
	)
	if err != nil {
		return nil, err
	}

	managerClient := builder.NewEcosystemManagerClient(
		cfg.Builder.BaseURL,
		builder.NewAuthenticatedClient(s.HTTPClient, s.Secrets, cfg.Builder.SecretID),
	)
	otpHandler := otp.NewAuthHandler(randomProvider, map[proto.IdentityType]otp.Sender{
		proto.IdentityType_Email: email.NewSender(managerClient, awsCfg, cfg.SES),
	})

	handlers := map[proto.AuthMode]auth.Handler{
		proto.AuthMode_IDToken:      o11y.NewTracedAuthHandler("idtoken.AuthProvider", idTokenHandler),
		proto.AuthMode_AuthCode:     o11y.NewTracedAuthHandler("authcode.AuthProvider", authCodeHandler),
		proto.AuthMode_AuthCodePKCE: o11y.NewTracedAuthHandler("authcode.AuthProvider", authCodeHandler),
		proto.AuthMode_OTP:          o11y.NewTracedAuthHandler("otp.AuthProvider", otpHandler),
	}
	return handlers, nil
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
