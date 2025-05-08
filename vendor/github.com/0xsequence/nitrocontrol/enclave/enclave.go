package enclave

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/tee-verifier/nitro"
)

// Enclave communicates with the Nitro Security Module to acquire an Attestation.
type Enclave struct {
	provider Provider
	kms      KMS

	privKey    *rsa.PrivateKey
	pkixPubKey []byte
}

// New returns a new Enclave with a random public key.
func New(ctx context.Context, provider Provider, kms KMS, optPrivKey ...*rsa.PrivateKey) (*Enclave, error) {
	e := &Enclave{
		provider: provider,
		kms:      kms,
	}

	if len(optPrivKey) > 0 && optPrivKey[0] != nil {
		e.privKey = optPrivKey[0]
	} else {
		sess, err := provider()
		if err != nil {
			return nil, fmt.Errorf("open NSM session: %w", err)
		}
		defer sess.Close()

		e.privKey, err = rsa.GenerateKey(sess, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate key pair: %w", err)
		}
	}

	var err error
	e.pkixPubKey, err = x509.MarshalPKIXPublicKey(&e.privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX pub key failed: %w", err)
	}
	return e, nil
}

// GetAttestation opens an NSM session and requests an Attestation that can then be used to perform
// cryptographic operations with AWS KMS.
//
// NOTE: Attestation must always be Closed manually after use.
func (e *Enclave) GetAttestation(ctx context.Context, nonce []byte, userData []byte) (*Attestation, error) {
	sess, err := e.provider()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}

	res, err := sess.Send(ctx, &request.Attestation{
		UserData:  userData,
		Nonce:     nonce,
		PublicKey: e.pkixPubKey,
	})
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("NSM attestation call: %w", err)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		_ = sess.Close()
		return nil, fmt.Errorf("attestation document is empty")
	}

	parsed, err := nitro.Parse(res.Attestation.Document)
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("parse attestation document: %w", err)
	}

	att := &Attestation{
		SignedAttestation: parsed,
		ReadCloser:        sess,
		document:          res.Attestation.Document,
		kms:               e.kms,
		key:               e.privKey,
	}
	return att, nil
}

// Measurements are calculated by the Nitro supervisor at runtime based on the enclave image.
type Measurements map[uint16]string

// GetMeasurements opens an NSM session and requests the PCR0 hash that is then returned
// as part of the Measurements struct.
func (e *Enclave) GetMeasurements(ctx context.Context, indices []uint16) (Measurements, error) {
	sess, err := e.provider()
	if err != nil {
		return nil, fmt.Errorf("open NSM session: %w", err)
	}
	defer sess.Close()

	measurements := make(Measurements)
	for _, index := range indices {
		res, err := sess.Send(ctx, &request.DescribePCR{Index: index})
		if err != nil {
			return nil, fmt.Errorf("NSM DescribePCR call: %w", err)
		}
		measurements[index] = hex.EncodeToString(res.DescribePCR.Data)
	}

	return measurements, nil
}
