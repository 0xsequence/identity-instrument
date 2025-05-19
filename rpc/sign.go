package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
	"github.com/0xsequence/identity-instrument/rpc/internal/ecosystem"
)

func (s *RPC) Sign(ctx context.Context, params *proto.SignParams) (string, error) {
	if params == nil {
		return "", proto.ErrInvalidRequest.WithCausef("params is required")
	}
	if params.AuthKey == nil {
		return "", proto.ErrInvalidRequest.WithCausef("auth key is required")
	}

	digestBytes := common.FromHex(params.Digest)
	sigBytes := common.FromHex(params.Signature)
	authKeyBytes := common.FromHex(params.AuthKey.PublicKey)

	switch params.AuthKey.KeyType {
	case proto.KeyType_P256K1:
		// Add Ethereum prefix to the hash
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(params.Digest), params.Digest)))

		// handle recovery byte
		if sigBytes[64] == 27 || sigBytes[64] == 28 {
			sigBytes[64] -= 27
		}

		// Recover the public key from the signature
		pubKey, err := crypto.Ecrecover(prefixedHash, sigBytes)
		if err != nil {
			return "", proto.ErrInvalidSignature.WithCausef("failed to recover public key: %w", err)
		}
		addr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

		if !strings.EqualFold(addr.String(), params.AuthKey.PublicKey) {
			return "", proto.ErrInvalidSignature.WithCausef("invalid auth key signature")
		}

	case proto.KeyType_P256R1:
		x, y := elliptic.Unmarshal(elliptic.P256(), authKeyBytes)
		if x == nil || y == nil {
			return "", proto.ErrInvalidSignature.WithCausef("invalid public key")
		}

		pub := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		digestHash := sha256.Sum256(digestBytes)
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:64])
		if !ecdsa.Verify(&pub, digestHash[:], r, s) {
			return "", proto.ErrInvalidSignature.WithCausef("invalid auth key signature")
		}

	default:
		return "", proto.ErrInvalidRequest.WithCausef("unknown key type")
	}

	dbAuthKey, found, err := s.AuthKeys.Get(ctx, ecosystem.FromContext(ctx), params.AuthKey.String())
	if err != nil {
		return "", proto.ErrDatabaseError.WithCausef("get auth key: %w", err)
	}
	if !found {
		return "", proto.ErrKeyNotFound
	}

	authKeyData, err := dbAuthKey.EncryptedData.Decrypt(ctx, attestation.FromContext(ctx), s.EncryptionPool)
	if err != nil {
		return "", proto.ErrEncryptionError.WithCausef("decrypt auth key data: %w", err)
	}

	if !dbAuthKey.CorrespondsTo(authKeyData) {
		return "", proto.ErrDataIntegrityError.WithCausef("auth key mismatch")
	}

	if authKeyData.Expiry.Before(time.Now()) {
		return "", proto.ErrKeyExpired
	}

	if authKeyData.SignerAddress != params.Signer {
		return "", proto.ErrDataIntegrityError.WithCausef("signer mismatch")
	}

	dbSigner, found, err := s.Signers.GetByAddress(ctx, ecosystem.FromContext(ctx), authKeyData.SignerAddress)
	if err != nil {
		return "", proto.ErrDatabaseError.WithCausef("get signer: %w", err)
	}
	if !found {
		return "", proto.ErrSignerNotFound
	}

	signerData, err := dbSigner.EncryptedData.Decrypt(ctx, attestation.FromContext(ctx), s.EncryptionPool)
	if err != nil {
		return "", proto.ErrEncryptionError.WithCausef("decrypt signer data: %w", err)
	}
	signer, err := crypto.HexToECDSA(signerData.PrivateKey[2:])
	if err != nil {
		return "", proto.ErrInternalError.WithCausef("create signer: %w", err)
	}
	if !dbSigner.CorrespondsTo(signerData, signer) {
		return "", proto.ErrDataIntegrityError.WithCausef("signer mismatch")
	}

	sigBytes, err = crypto.Sign(digestBytes, signer)
	if err != nil {
		return "", proto.ErrInternalError.WithCausef("sign digest: %w", err)
	}

	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}

	return hexutil.Encode(sigBytes), nil
}
