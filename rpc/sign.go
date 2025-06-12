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
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
)

func (s *RPC) Sign(ctx context.Context, params *proto.SignParams) (string, error) {
	log := o11y.LoggerFromContext(ctx)

	scope, err := s.getScope(ctx, params)
	if err != nil {
		return "", proto.ErrInvalidRequest.WithCausef("valid scope is required")
	}

	if params == nil {
		return "", proto.ErrInvalidRequest.WithCausef("params is required")
	}
	if !params.AuthKey.IsValid() {
		return "", proto.ErrInvalidRequest.WithCausef("valid auth key is required")
	}

	digestBytes := common.FromHex(params.Digest)
	sigBytes := common.FromHex(params.Signature)

	switch params.AuthKey.KeyType {
	case proto.KeyType_Secp256k1:
		// Add Ethereum prefix to the hash
		prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(params.Digest), params.Digest)))

		// handle recovery byte
		if sigBytes[64] == 27 || sigBytes[64] == 28 {
			sigBytes[64] -= 27
		}

		// Recover the public key from the signature
		pubKey, err := crypto.Ecrecover(prefixedHash, sigBytes)
		if err != nil {
			log.Error("failed to recover public key", "key_type", "secp256k1", "error", err)
			return "", proto.ErrInvalidSignature
		}
		addr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

		if !strings.EqualFold(addr.String(), params.AuthKey.Address) {
			log.Error("invalid auth key signature", "key_type", "secp256k1")
			return "", proto.ErrInvalidSignature
		}

	case proto.KeyType_Secp256r1:
		pubKeyBytes := common.FromHex(params.AuthKey.Address)
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
		if x == nil || y == nil {
			log.Error("invalid public key", "key_type", "secp256r1")
			return "", proto.ErrInvalidSignature
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
			log.Error("invalid auth key signature", "key_type", "secp256r1")
			return "", proto.ErrInvalidSignature
		}

	default:
		return "", proto.ErrInvalidRequest.WithCausef("unknown key type")
	}

	dbAuthKey, found, err := s.AuthKeys.Get(ctx, scope, params.AuthKey)
	if err != nil {
		log.Error("failed to get auth key", "error", err)
		return "", proto.ErrDatabaseError
	}
	if !found {
		return "", proto.ErrKeyNotFound
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

	signerData, err := dbSigner.EncryptedData.Decrypt(ctx, attestation.FromContext(ctx), s.EncryptionPool)
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

	sigBytes, err = crypto.Sign(digestBytes, signer)
	if err != nil {
		log.Error("failed to sign digest", "error", err)
		return "", proto.ErrInternalError
	}

	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}

	return hexutil.Encode(sigBytes), nil
}
