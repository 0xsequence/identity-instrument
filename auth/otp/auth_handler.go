package otp

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/proto"
)

type AuthHandler struct {
	senders        map[proto.IdentityType]Sender
	randomProvider func(ctx context.Context) io.Reader
}

var _ auth.Handler = (*AuthHandler)(nil)

func NewAuthHandler(
	randomProvider func(ctx context.Context) io.Reader,
	senders map[proto.IdentityType]Sender,
) *AuthHandler {
	return &AuthHandler{
		senders:        senders,
		randomProvider: randomProvider,
	}
}

func (h *AuthHandler) Supports(identityType proto.IdentityType) bool {
	_, ok := h.senders[identityType]
	return ok
}

// Commit for OTP ignores any preexisting auth commitment. Instead, if called multiple times, the auth commitment
// is replaced. This allows the user to resend the verification code in case of issues. Note that this invalidates the
// previous auth commitment - only the most recent one is stored and used in Verify.
func (h *AuthHandler) Commit(
	ctx context.Context,
	authID proto.AuthID,
	_commitment *proto.AuthCommitmentData,
	signer *proto.SignerData,
	authKey *proto.AuthKey,
	_metadata map[string]string,
	storeFn auth.StoreCommitmentFn,
) (resVerifier string, loginHint string, resChallenge string, err error) {
	sender, ok := h.senders[authID.IdentityType]
	if !ok {
		return "", "", "", fmt.Errorf("unsupported identity type: %v", authID.IdentityType)
	}

	var recipient string
	if signer != nil {
		recipient = signer.Identity.Subject
	} else {
		recipient, err = sender.NormalizeRecipient(authID.Verifier)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid recipient: %w", err)
		}
		loginHint = recipient
	}

	randomSource := h.randomProvider(ctx)

	// generate the secret verification code to be sent to the user
	secretCode, err := randomDigits(randomSource, 6)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate secret code: %w", err)
	}
	// client salt is sent back to the client in the intent response
	clientSalt, err := randomHex(randomSource, 12)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate client salt: %w", err)
	}
	// server salt is sent to the WaaS API and stored in the auth session
	serverSalt, err := randomHex(randomSource, 12)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate server salt: %w", err)
	}

	// clientAnswer is the value that we expect the client to produce
	clientAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(clientSalt + secretCode)))

	// serverAnswer is the value we compare the answer against during verification
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(serverSalt + clientAnswer)))

	expiresAt := time.Now().Add(30 * time.Minute)
	commitment := &proto.AuthCommitmentData{
		Ecosystem:    authID.Ecosystem,
		AuthKey:      authKey,
		AuthMode:     authID.AuthMode,
		IdentityType: authID.IdentityType,
		Handle:       recipient,
		Challenge:    serverSalt,   // the SERVER salt is a challenge in server's context
		Answer:       serverAnswer, // the final answer, after hashing clientAnswer with serverSalt
		Expiry:       expiresAt,
		Metadata:     nil, // uses no metadata
	}

	if signer != nil {
		loginHint = signer.Identity.Subject
		commitment.Signer, err = signer.Address()
		if err != nil {
			return "", "", "", fmt.Errorf("failed to get signer address: %w", err)
		}
	}

	if err := storeFn(ctx, commitment); err != nil {
		return "", "", "", fmt.Errorf("failed to store commitment: %w", err)
	}

	if err := sender.SendOTP(ctx, authID.Ecosystem, recipient, secretCode); err != nil {
		return "", "", "", fmt.Errorf("failed to send OTP: %w", err)
	}

	// Client should combine the challenge from the response with the code from the email address and hash it.
	// The resulting value is the clientAnswer that is then send with the RegisterAuth RPC and passed to Verify.
	resChallenge = clientSalt // the CLIENT salt is a challenge in client's context
	resVerifier = commitment.Verifier()
	return resVerifier, loginHint, resChallenge, nil
}

// Verify requires the auth commitment to exist as it contains the challenge and final answer. The challenge (server salt)
// from the auth commitment is combined with the client's answer and the resulting value compared with the final answer.
// Verify returns the identity if this is successful.
func (h *AuthHandler) Verify(
	ctx context.Context,
	commitment *proto.AuthCommitmentData,
	authKey *proto.AuthKey,
	answer string,
) (proto.Identity, error) {
	if commitment == nil {
		return proto.Identity{}, fmt.Errorf("commitment not found")
	}

	// challenge here is the server salt; combined with the client's answer and hashed it produces the serverAnswer
	serverAnswer := hexutil.Encode(ethcrypto.Keccak256([]byte(commitment.Challenge + answer)))
	if serverAnswer != commitment.Answer {
		return proto.Identity{}, fmt.Errorf("incorrect answer")
	}
	identity := proto.Identity{
		Type:    commitment.IdentityType,
		Subject: commitment.Handle,
	}
	return identity, nil
}

func randomDigits(source io.Reader, n int) (string, error) {
	const digits = "0123456789"
	result := make([]byte, n)

	for i := range result {
		num, err := rand.Int(source, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		result[i] = digits[num.Int64()]
	}

	return string(result), nil
}

func randomHex(source io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := source.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}
