package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/attestation"
	"github.com/0xsequence/identity-instrument/rpc/auth"
	"github.com/0xsequence/identity-instrument/rpc/auth/email"
	"github.com/0xsequence/identity-instrument/rpc/auth/oauth"
	"github.com/0xsequence/identity-instrument/rpc/auth/oidc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/goware/cachestore/memlru"
)

func (s *RPC) InitiateAuth(ctx context.Context, params *proto.InitiateAuthParams) (string, string, error) {
	att := attestation.FromContext(ctx)

	if params == nil {
		return "", "", fmt.Errorf("params is nil")
	}

	authProvider, err := s.getAuthProvider(params.AuthMode)
	if err != nil {
		return "", "", fmt.Errorf("get auth provider: %w", err)
	}

	if !authProvider.Supports(params.IdentityType) {
		return "", "", fmt.Errorf("unsupported identity type: %v", params.IdentityType)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		EcosystemID:  params.EcosystemID,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	if authID.Verifier != "" {
		dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
		if err != nil {
			return "", "", fmt.Errorf("getting commitment: %w", err)
		}
		if found && dbCommitment != nil {
			commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
			if err != nil {
				return "", "", fmt.Errorf("decrypting commitment data: %w", err)
			}
		}
	}

	storeFn := func(ctx context.Context, commitment *proto.AuthCommitmentData) error {
		att := attestation.FromContext(ctx)

		encryptedData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], commitment)
		if err != nil {
			return fmt.Errorf("encrypting commitment: %w", err)
		}

		dbCommitment := &data.AuthCommitment{
			ID: data.AuthID{
				EcosystemID:  commitment.EcosystemID,
				AuthMode:     commitment.AuthMode,
				IdentityType: commitment.IdentityType,
				Verifier:     commitment.Verifier,
			},
			EncryptedData: encryptedData,
		}

		if !dbCommitment.CorrespondsTo(commitment) {
			return fmt.Errorf("invalid commitment")
		}

		if err := s.AuthCommitments.Put(ctx, dbCommitment); err != nil {
			return fmt.Errorf("putting verification context: %w", err)
		}
		return nil
	}

	return authProvider.InitiateAuth(ctx, authID, commitment, params.AuthKey, params.Metadata, storeFn)
}

func (s *RPC) RegisterAuth(ctx context.Context, params *proto.RegisterAuthParams) (string, error) {
	att := attestation.FromContext(ctx)

	authProvider, err := s.getAuthProvider(params.AuthMode)
	if err != nil {
		return "", fmt.Errorf("get auth provider: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		EcosystemID:  params.EcosystemID,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		return "", fmt.Errorf("get commitment: %w", err)
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
		if err != nil {
			return "", fmt.Errorf("decrypt commitment data: %w", err)
		}

		// TODO: attempts

		if time.Now().After(commitment.Expiry) {
			return "", fmt.Errorf("commitment expired")
		}

		if !dbCommitment.CorrespondsTo(commitment) {
			return "", fmt.Errorf("commitment mismatch")
		}
	}

	ident, err := authProvider.Verify(ctx, commitment, params.AuthKey, params.Answer)
	if err != nil {
		if commitment != nil {
			// TODO: increment attempt and store it back
		}
		return "", fmt.Errorf("verify answer: %w", err)
	}

	// always use normalized email address
	ident.Email = email.Normalize(ident.Email)

	dbSigner, signerFound, err := s.Signers.GetByIdentity(ctx, params.EcosystemID, ident)
	if err != nil {
		return "", fmt.Errorf("retrieve signer: %w", err)
	}

	if !signerFound {
		signerWallet, err := ethwallet.NewWalletFromRandomEntropy()
		if err != nil {
			return "", fmt.Errorf("generate wallet: %w", err)
		}
		signerData := &proto.SignerData{
			EcosystemID: params.EcosystemID,
			Identity:    &ident,
			PrivateKey:  signerWallet.PrivateKeyHex(),
		}
		encData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], signerData)
		if err != nil {
			return "", fmt.Errorf("encrypt signer data: %w", err)
		}
		dbSigner = &data.Signer{
			EcosystemID:   params.EcosystemID,
			Address:       signerWallet.Address().Hex(),
			Identity:      data.Identity(ident),
			EncryptedData: encData,
		}
		if err := s.Signers.Put(ctx, dbSigner); err != nil {
			return "", fmt.Errorf("put signer: %w", err)
		}
	}

	ttl := 5 * time.Minute
	authKeyData := &proto.AuthKeyData{
		EcosystemID:   params.EcosystemID,
		SignerAddress: dbSigner.Address,
		KeyType:       params.AuthKey.KeyType,
		PublicKey:     params.AuthKey.PublicKey,
		Expiry:        time.Now().Add(ttl),
	}

	encData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], authKeyData)
	if err != nil {
		return "", fmt.Errorf("encrypt auth key data: %w", err)
	}

	dbAuthKey := &data.AuthKey{
		EcosystemID:   params.EcosystemID,
		KeyID:         params.AuthKey.String(),
		EncryptedData: encData,
	}
	if err := s.AuthKeys.Put(ctx, dbAuthKey); err != nil {
		return "", fmt.Errorf("put auth key: %w", err)
	}

	return dbSigner.Address, nil
}

func (s *RPC) getAuthProvider(authMode proto.AuthMode) (auth.Provider, error) {
	authProvider, ok := s.AuthProviders[authMode]
	if !ok {
		return nil, fmt.Errorf("unknown auth mode: %v", authMode)
	}
	return authProvider, nil
}

func makeAuthProviders(client HTTPClient, awsCfg aws.Config, cfg *config.Config) (map[proto.AuthMode]auth.Provider, error) {
	cacheBackend := memlru.Backend(1024)
	oidcProvider, err := oidc.NewAuthProvider(cacheBackend, client)
	if err != nil {
		return nil, err
	}

	secretProvider := oauth.SecretProviderFunc(func(ctx context.Context, iss string, aud string) (string, error) {
		// TODO: get secret from secret manager
		return "SECRET", nil
	})
	oauthProvider, err := oauth.NewAuthProvider(client, oidcProvider, secretProvider)
	if err != nil {
		return nil, err
	}

	providers := map[proto.AuthMode]auth.Provider{
		proto.AuthMode_IDToken:      oidcProvider, // auth.NewTracedProvider("oidc.AuthProvider", oidcProvider),
		proto.AuthMode_AuthCodePKCE: oauthProvider,
	}
	return providers, nil
}
