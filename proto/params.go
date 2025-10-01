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

	return nil
}
