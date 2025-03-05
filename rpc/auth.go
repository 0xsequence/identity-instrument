package rpc

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/attestation"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/auth/authcode"
	"github.com/0xsequence/identity-instrument/auth/idtoken"
	"github.com/0xsequence/identity-instrument/auth/otp"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goware/cachestore/memlru"
)

func (s *RPC) InitiateAuth(ctx context.Context, params *proto.InitiateAuthParams) (string, string, error) {
	if params == nil {
		return "", "", fmt.Errorf("params is nil")
	}

	authHandler, err := s.getAuthHandler(params.AuthMode)
	if err != nil {
		return "", "", fmt.Errorf("get auth handler: %w", err)
	}

	if !authHandler.Supports(params.IdentityType) {
		return "", "", fmt.Errorf("unsupported identity type: %v", params.IdentityType)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		Ecosystem:    params.Ecosystem,
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
			commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, s.EncryptionPool)
			if err != nil {
				return "", "", fmt.Errorf("decrypting commitment data: %w", err)
			}
		}
	}

	storeFn := func(ctx context.Context, commitment *proto.AuthCommitmentData) error {
		encryptedData, err := data.Encrypt(ctx, s.EncryptionPool, commitment)
		if err != nil {
			return fmt.Errorf("encrypting commitment: %w", err)
		}

		dbCommitment := &data.AuthCommitment{
			ID: data.AuthID{
				Ecosystem:    commitment.Ecosystem,
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

	return authHandler.Commit(ctx, authID, commitment, params.AuthKey, params.Metadata, storeFn)
}

func (s *RPC) RegisterAuth(ctx context.Context, params *proto.RegisterAuthParams) (string, error) {
	att := attestation.FromContext(ctx)

	authHandler, err := s.getAuthHandler(params.AuthMode)
	if err != nil {
		return "", fmt.Errorf("get auth handler: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := proto.AuthID{
		Ecosystem:    params.Ecosystem,
		AuthMode:     params.AuthMode,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		return "", fmt.Errorf("get commitment: %w", err)
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, s.EncryptionPool)
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

	ident, err := authHandler.Verify(ctx, commitment, params.AuthKey, params.Answer)
	if err != nil {
		if commitment != nil {
			// TODO: increment attempt and store it back
		}
		return "", fmt.Errorf("verify answer: %w", err)
	}

	// always use normalized email address
	ident.Email = otp.NormalizeEmail(ident.Email)

	dbSigner, signerFound, err := s.Signers.GetByIdentity(ctx, params.Ecosystem, ident)
	if err != nil {
		return "", fmt.Errorf("retrieve signer: %w", err)
	}

	if !signerFound {
		signer, err := ecdsa.GenerateKey(secp256k1.S256(), att)
		if err != nil {
			return "", fmt.Errorf("generate signer: %w", err)
		}

		signerData := &proto.SignerData{
			Ecosystem:  params.Ecosystem,
			Identity:   &ident,
			PrivateKey: hexutil.Encode(crypto.FromECDSA(signer)),
		}
		encData, err := data.Encrypt(ctx, s.EncryptionPool, signerData)
		if err != nil {
			return "", fmt.Errorf("encrypt signer data: %w", err)
		}
		dbSigner = &data.Signer{
			Ecosystem:     params.Ecosystem,
			Address:       crypto.PubkeyToAddress(signer.PublicKey).Hex(),
			Identity:      data.Identity(ident),
			EncryptedData: encData,
		}
		if err := s.Signers.Put(ctx, dbSigner); err != nil {
			return "", fmt.Errorf("put signer: %w", err)
		}
	}

	ttl := 5 * time.Minute
	authKeyData := &proto.AuthKeyData{
		Ecosystem:     params.Ecosystem,
		SignerAddress: dbSigner.Address,
		KeyType:       params.AuthKey.KeyType,
		PublicKey:     params.AuthKey.PublicKey,
		Expiry:        time.Now().Add(ttl),
	}

	encData, err := data.Encrypt(ctx, s.EncryptionPool, authKeyData)
	if err != nil {
		return "", fmt.Errorf("encrypt auth key data: %w", err)
	}

	dbAuthKey := &data.AuthKey{
		Ecosystem:     params.Ecosystem,
		KeyID:         params.AuthKey.String(),
		EncryptedData: encData,
	}
	if err := s.AuthKeys.Put(ctx, dbAuthKey); err != nil {
		return "", fmt.Errorf("put auth key: %w", err)
	}

	return dbSigner.Address, nil
}

func (s *RPC) getAuthHandler(authMode proto.AuthMode) (auth.Handler, error) {
	authHandler, ok := s.AuthHandlers[authMode]
	if !ok {
		return nil, fmt.Errorf("unknown auth mode: %v", authMode)
	}
	return authHandler, nil
}

func (s *RPC) makeAuthHandlers() (map[proto.AuthMode]auth.Handler, error) {
	cacheBackend := memlru.Backend(1024)
	idTokenHandler, err := idtoken.NewAuthHandler(cacheBackend, s.HTTPClient)
	if err != nil {
		return nil, err
	}

	secretProvider := authcode.SecretProviderFunc(func(ctx context.Context, ecosystem string, iss string, aud string) (string, error) {
		secretName := ecosystem + "/" + hexutil.Encode(crypto.Keccak256([]byte(fmt.Sprintf("%s#%s", iss, aud))))

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
	authCodeHandler, err := authcode.NewAuthHandler(cacheBackend, s.HTTPClient, idTokenHandler, secretProvider)
	if err != nil {
		return nil, err
	}

	handlers := map[proto.AuthMode]auth.Handler{
		proto.AuthMode_IDToken:      idTokenHandler, // auth.NewTracedProvider("oidc.AuthProvider", oidcProvider),
		proto.AuthMode_AuthCodePKCE: authCodeHandler,
	}
	return handlers, nil
}
