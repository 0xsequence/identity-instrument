package proto

import (
	"fmt"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
)

func (p *CommitVerifierParams) Validate() error {
	if p == nil {
		return fmt.Errorf("params is required")
	}

	if p.Scope != "" && !p.Scope.IsValid() {
		return fmt.Errorf("invalid scope: %s", p.Scope)
	}

	if !p.IdentityType.Is(IdentityType_Email, IdentityType_OIDC) {
		return fmt.Errorf("invalid identity type: %s", p.IdentityType)
	}

	if !p.AuthMode.Is(AuthMode_OTP, AuthMode_IDToken, AuthMode_AccessToken, AuthMode_AuthCode, AuthMode_AuthCodePKCE) {
		return fmt.Errorf("invalid auth mode: %s", p.AuthMode)
	}

	if p.Signer != nil && !p.Signer.IsValid() {
		return fmt.Errorf("invalid signer: %s", p.Signer)
	}

	if p.Handle != "" && len(p.Handle) > 250 {
		return fmt.Errorf("handle is too long: %s", p.Handle)
	}

	if p.Metadata != nil {
		if len(p.Metadata) > 10 {
			return fmt.Errorf("too many metadata entries: %d", len(p.Metadata))
		}
		for k, v := range p.Metadata {
			if len(k) > 50 {
				return fmt.Errorf("metadata key is too long: %s", k)
			}
			if len(v) > 250 {
				return fmt.Errorf("metadata value for key %s is too long: %s", k, v)
			}
		}
	}

	return nil
}

func (p *CompleteAuthParams) Validate() error {
	if p == nil {
		return fmt.Errorf("params is required")
	}

	if p.Scope != "" && !p.Scope.IsValid() {
		return fmt.Errorf("invalid scope: %s", p.Scope)
	}

	if !p.IdentityType.Is(IdentityType_Email, IdentityType_OIDC) {
		return fmt.Errorf("invalid identity type: %s", p.IdentityType)
	}

	if !p.AuthMode.Is(AuthMode_OTP, AuthMode_IDToken, AuthMode_AccessToken, AuthMode_AuthCode, AuthMode_AuthCodePKCE) {
		return fmt.Errorf("invalid auth mode: %s", p.AuthMode)
	}

	if !p.SignerType.Is(KeyType_Ethereum_Secp256k1, KeyType_WebCrypto_Secp256r1) {
		return fmt.Errorf("invalid signer type: %s", p.SignerType)
	}

	if p.Verifier != "" && len(p.Verifier) > 250 {
		return fmt.Errorf("verifier is too long: %s", p.Verifier)
	}

	if p.Answer != "" && len(p.Answer) > 2048 {
		return fmt.Errorf("answer is too long: %s", p.Answer)
	}

	return nil
}

func (p *SignParams) Validate() error {
	if p == nil {
		return fmt.Errorf("params is required")
	}

	if p.Scope != "" && !p.Scope.IsValid() {
		return fmt.Errorf("invalid scope: %s", p.Scope)
	}

	if !p.Signer.IsValid() {
		return fmt.Errorf("invalid signer: %s", p.Signer)
	}

	digestBytes, err := hexutil.Decode(p.Digest)
	if err != nil || len(digestBytes) != 32 {
		return fmt.Errorf("invalid digest: %s", p.Digest)
	}

	if p.Nonce != "" && len(p.Nonce) > 64 {
		return fmt.Errorf("nonce is too long: %s", p.Nonce)
	}

	return nil
}
