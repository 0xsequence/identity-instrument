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
)

func (s *RPC) CommitVerifier(ctx context.Context, params *proto.CommitVerifierParams) (string, string, string, error) {
	att := attestation.FromContext(ctx)

	if params == nil {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("params is required")
	}
	if !params.AuthKey.IsValid() {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("valid auth key is required")
	}
	if !params.Scope.IsValid() {
		return "", "", "", proto.ErrInvalidRequest.WithCausef("valid scope is required")
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
		Scope:        params.Scope,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Handle,
	}

	var signer *proto.SignerData
	if params.Signer.IsValid() {
		authID.Verifier = params.Signer.String()
		dbSigner, found, err := s.Signers.GetByAddress(ctx, params.Scope, *params.Signer)
		if err != nil {
			return "", "", "", proto.ErrDatabaseError.WithCausef("get signer: %w", err)
		}
		if !found {
			return "", "", "", proto.ErrInvalidRequest.WithCausef("signer not found")
		}
		signer, err = dbSigner.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
		if err != nil {
			return "", "", "", proto.ErrEncryptionError.WithCausef("decrypt signer data: %w", err)
		}
		if signer.Identity.Type != params.IdentityType {
			return "", "", "", proto.ErrDataIntegrityError.WithCausef("signer identity type mismatch")
		}
	}

	if authID.Verifier != "" {
		dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
		if err != nil {
			return "", "", "", proto.ErrDatabaseError.WithCausef("getting commitment: %w", err)
		}
		if found && dbCommitment != nil {
			commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
			if err != nil {
				return "", "", "", proto.ErrEncryptionError.WithCausef("decrypting commitment data: %w", err)
			}
		}
	}

	storeFn := func(ctx context.Context, commitment *proto.AuthCommitmentData) error {
		encryptedData, err := data.Encrypt(ctx, att, s.EncryptionPool, commitment)
		if err != nil {
			return proto.ErrEncryptionError.WithCausef("encrypting commitment: %w", err)
		}

		dbCommitment := &data.AuthCommitment{
			ID: data.AuthID{
				Scope:        commitment.Scope,
				AuthMode:     commitment.AuthMode,
				IdentityType: commitment.IdentityType,
				Verifier:     commitment.Verifier(),
			},
			EncryptedData: encryptedData,
		}

		if !dbCommitment.CorrespondsTo(commitment) {
			return proto.ErrDataIntegrityError.WithCausef("invalid commitment")
		}

		if err := s.AuthCommitments.Put(ctx, dbCommitment); err != nil {
			return proto.ErrDatabaseError.WithCausef("putting verification context: %w", err)
		}
		return nil
	}

	return authHandler.Commit(ctx, authID, commitment, signer, params.AuthKey, params.Metadata, storeFn)
}

func (s *RPC) CompleteAuth(ctx context.Context, params *proto.CompleteAuthParams) (*proto.Key, error) {
	att := attestation.FromContext(ctx)

	if params == nil {
		return nil, proto.ErrInvalidRequest.WithCausef("params is required")
	}
	if !params.AuthKey.IsValid() {
		return nil, proto.ErrInvalidRequest.WithCausef("valid auth key is required")
	}
	if !params.Scope.IsValid() {
		return nil, proto.ErrInvalidRequest.WithCausef("valid scope is required")
	}

	// Currently we only support secp256k1 signers
	if !params.SignerType.Is(proto.KeyType_Secp256k1) {
		return nil, proto.ErrInvalidRequest.WithCausef("signer key type must be secp256k1")
	}

	authHandler, err := s.getAuthHandler(params.AuthMode)
	if err != nil {
		return nil, proto.ErrInvalidRequest.WithCausef("get auth handler: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		Scope:        params.Scope,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		return nil, proto.ErrDatabaseError.WithCausef("get commitment: %w", err)
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.EncryptionPool)
		if err != nil {
			return nil, proto.ErrEncryptionError.WithCausef("decrypt commitment data: %w", err)
		}

		if commitment.Attempts >= 3 {
			return nil, proto.ErrTooManyAttempts
		}

		if time.Now().After(commitment.Expiry) {
			return nil, proto.ErrChallengeExpired
		}

		if !dbCommitment.CorrespondsTo(commitment) || commitment.Scope != params.Scope {
			return nil, proto.ErrDataIntegrityError.WithCausef("commitment mismatch")
		}
	}

	ident, err := authHandler.Verify(ctx, commitment, params.AuthKey, params.Answer)
	if err != nil {
		if commitment != nil {
			commitment.Attempts += 1
			encryptedData, err := data.Encrypt(ctx, att, s.EncryptionPool, commitment)
			if err != nil {
				return nil, proto.ErrEncryptionError.WithCausef("encrypting commitment: %w", err)
			}
			if err := s.AuthCommitments.UpdateData(ctx, dbCommitment, encryptedData); err != nil {
				return nil, proto.ErrDatabaseError.WithCausef("updating commitment: %w", err)
			}
		}
		return nil, err
	}

	// always use normalized email address
	ident.Email = email.Normalize(ident.Email)

	dbSigner, signerFound, err := s.Signers.GetByIdentity(ctx, ident, params.Scope, params.SignerType)
	if err != nil {
		return nil, proto.ErrDatabaseError.WithCausef("retrieve signer: %w", err)
	}

	if dbSigner != nil && commitment.Signer.IsValid() && !dbSigner.CorrespondsToProtoKey(commitment.Signer) {
		return nil, proto.ErrDataIntegrityError.WithCausef("signer address mismatch")
	}

	if !signerFound {
		if commitment.Signer.IsValid() {
			return nil, proto.ErrDataIntegrityError.WithCausef("signer not found")
		}

		signer, err := ecdsa.GenerateKey(secp256k1.S256(), att)
		if err != nil {
			return nil, proto.ErrInternalError.WithCausef("generate signer: %w", err)
		}

		signerData := &proto.SignerData{
			Scope:      params.Scope,
			Identity:   &ident,
			KeyType:    params.SignerType,
			PrivateKey: hexutil.Encode(crypto.FromECDSA(signer)),
		}
		encData, err := data.Encrypt(ctx, att, s.EncryptionPool, signerData)
		if err != nil {
			return nil, proto.ErrEncryptionError.WithCausef("encrypt signer data: %w", err)
		}
		dbSigner = &data.Signer{
			ScopedKeyType: data.ScopedKeyType{
				Scope:   params.Scope,
				KeyType: params.SignerType,
			},
			Address:       strings.ToLower(crypto.PubkeyToAddress(signer.PublicKey).Hex()),
			Identity:      data.Identity(ident),
			EncryptedData: encData,
		}
		if err := s.Signers.Put(ctx, dbSigner); err != nil {
			return nil, proto.ErrDatabaseError.WithCausef("put signer: %w", err)
		}
	}

	ttl := 5 * time.Minute
	authKeyData := &proto.AuthKeyData{
		Scope:   params.Scope,
		Signer:  dbSigner.Key(),
		AuthKey: params.AuthKey,
		Expiry:  time.Now().Add(ttl),
	}

	encData, err := data.Encrypt(ctx, att, s.EncryptionPool, authKeyData)
	if err != nil {
		return nil, proto.ErrEncryptionError.WithCausef("encrypt auth key data: %w", err)
	}

	dbAuthKey := &data.AuthKey{
		Scope:         params.Scope,
		KeyID:         params.AuthKey.String(),
		EncryptedData: encData,
	}
	if err := s.AuthKeys.Put(ctx, dbAuthKey); err != nil {
		return nil, proto.ErrDatabaseError.WithCausef("put auth key: %w", err)
	}

	res := dbSigner.Key()
	return &res, nil
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
	idTokenHandler, err := idtoken.NewAuthHandler(cacheBackend, s.HTTPClient)
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
	authCodeHandler, err := authcode.NewAuthHandler(cacheBackend, s.HTTPClient, idTokenHandler, secretProvider, randomProvider)
	if err != nil {
		return nil, err
	}

	builderClient := builder.NewBuilderClient(
		cfg.Builder.BaseURL,
		builder.NewAuthenticatedClient(s.HTTPClient, s.Secrets, cfg.Builder.SecretID),
	)
	otpHandler := otp.NewAuthHandler(randomProvider, map[proto.IdentityType]otp.Sender{
		proto.IdentityType_Email: email.NewSender(builderClient, awsCfg, cfg.SES),
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
