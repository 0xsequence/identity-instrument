package rpc

import (
	"context"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
)

func (s *RPC) Sign(ctx context.Context, params *proto.SignParams, authKey *proto.Key, signature string) (string, error) {
	log := o11y.LoggerFromContext(ctx)

	scope, err := s.getScope(ctx, params)
	if err != nil {
		return "", proto.ErrInvalidRequest.WithCausef("valid scope is required")
	}

	if err := params.Validate(); err != nil {
		return "", proto.ErrInvalidRequest.WithCausef("invalid params: %w", err)
	}

	dbAuthKey, found, err := s.AuthKeys.Get(ctx, scope, *authKey)
	if err != nil {
		log.Error("failed to get auth key", "error", err)
		return "", proto.ErrDatabaseError
	}
	if !found {
		return "", proto.ErrKeyNotFound
	}

	if err := s.checkRateLimit(ctx, dbAuthKey); err != nil {
		return "", err
	}

	authKeyData, err := dbAuthKey.EncryptedData.Decrypt(ctx, attestation.FromContext(ctx), s.EncryptionPool)
	if err != nil {
		log.Error("failed to decrypt auth key data", "error", err)
		return "", proto.ErrEncryptionError
	}

	if !dbAuthKey.CorrespondsTo(authKeyData) {
		log.Error("auth key mismatch")
		return "", proto.ErrDataIntegrityError
	}

	if authKeyData.Expiry.Before(time.Now()) {
		return "", proto.ErrKeyExpired
	}

	if authKeyData.Signer != params.Signer {
		log.Error("signer mismatch")
		return "", proto.ErrDataIntegrityError
	}

	dbSigner, found, err := s.Signers.GetByAddress(ctx, scope, authKeyData.Signer)
	if err != nil {
		log.Error("failed to get signer", "error", err)
		return "", proto.ErrDatabaseError
	}
	if !found {
		return "", proto.ErrSignerNotFound
	}

	signerData, err := dbSigner.Decrypt(ctx, attestation.FromContext(ctx), s.EncryptionPool)
	if err != nil {
		log.Error("failed to decrypt signer data", "error", err)
		return "", proto.ErrEncryptionError
	}
	signer, err := crypto.HexToECDSA(signerData.PrivateKey[2:])
	if err != nil {
		log.Error("failed to create signer", "error", err)
		return "", proto.ErrInternalError
	}
	if !dbSigner.CorrespondsToData(signerData, signer) {
		log.Error("signer mismatch")
		return "", proto.ErrDataIntegrityError
	}

	digestBytes := common.FromHex(params.Digest)
	sigBytes, err := crypto.Sign(digestBytes, signer)
	if err != nil {
		log.Error("failed to sign digest", "error", err)
		return "", proto.ErrInternalError
	}

	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}

	return hexutil.Encode(sigBytes), nil
}

func (s *RPC) checkRateLimit(ctx context.Context, authKey *data.AuthKey) error {
	if !s.Config.RateLimit.Enabled {
		return nil
	}

	log := o11y.LoggerFromContext(ctx)
	now := time.Now()

	// Reset usage window if enough time has passed
	if now.After(authKey.UsageWindowStart.Add(s.Config.RateLimit.WindowSize)) {
		if err := s.AuthKeys.ResetUsageWindow(ctx, authKey, now); err != nil {
			log.Error("failed to reset usage window", "error", err)
			return proto.ErrDatabaseError
		}
		return nil
	}

	if authKey.UsageCountInWindow >= s.Config.RateLimit.UsageLimit {
		return proto.ErrUsageLimitExceeded
	}

	if err := s.AuthKeys.IncrementUsageCount(ctx, authKey); err != nil {
		log.Error("failed to increment usage count", "error", err)
		return proto.ErrDatabaseError
	}
	return nil
}
