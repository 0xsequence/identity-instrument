package tests

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	protoadmin "github.com/0xsequence/identity-instrument/proto/admin"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateCipherKey(t *testing.T) {
	ep, terminate := initLocalstack()
	defer terminate()
	svc := initRPC(t, ep, nil, func(cfg *config.Config) {
		cfg.Encryption[0].PoolSize = 1
	})
	att, err := svc.Enclave.GetAttestation(context.Background(), nil, nil)
	require.NoError(t, err)
	defer att.Close()

	originalKey, _, err := svc.EncryptionPool.GenerateKey(context.Background(), att, 0)
	require.NoError(t, err)

	_, err = svc.CipherKeys.Create(context.Background(), originalKey)
	require.NoError(t, err)

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := protoadmin.NewIdentityInstrumentAdminClient(srv.URL, http.DefaultClient)

	err = c.RotateCipherKey(context.Background(), originalKey.KeyRef)
	require.NoError(t, err)

	key, found, err := svc.CipherKeys.Get(context.Background(), 0, 0, false)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, key)

	key, found, err = svc.CipherKeys.GetLatestByKeyRef(context.Background(), originalKey.KeyRef, false)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, key.KeyIndex < 0, "key index should be negative")

	err = svc.EncryptionPool.VerifyKey(context.Background(), att, key)
	require.NoError(t, err)
}

func TestRefreshEncryptedData(t *testing.T) {
	ep, terminate := initLocalstack()
	defer terminate()
	svc := initRPC(t, ep, nil, func(cfg *config.Config) {
		cfg.Encryption[0].PoolSize = 1
	})

	att, err := svc.Enclave.GetAttestation(context.Background(), nil, nil)
	require.NoError(t, err)
	defer att.Close()

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := protoadmin.NewIdentityInstrumentAdminClient(srv.URL, http.DefaultClient)

	// Create a key that will be originally used to encrypt data, then rotated
	oldKey, _, err := svc.EncryptionPool.GenerateKey(context.Background(), att, 0)
	require.NoError(t, err)

	// Generate a few signers
	for i := 0; i < 100; i++ {
		subject := fmt.Sprintf("test%d@test.com", i)
		wallet, err := ecdsa.GenerateKey(secp256k1.S256(), att)
		require.NoError(t, err)

		signerData := &proto.SignerData{
			Scope:      proto.Scope("test"),
			KeyType:    proto.KeyType_Ethereum_Secp256k1,
			Identity:   &proto.Identity{Type: proto.IdentityType_Email, Subject: subject},
			PrivateKey: hexutil.Encode(crypto.FromECDSA(wallet)),
		}
		encData, err := data.Encrypt(context.Background(), att, svc.EncryptionPool, signerData)
		require.NoError(t, err)
		require.Equal(t, oldKey.KeyRef, encData.CipherKeyRef)

		signer := &data.Signer{
			ScopedKeyType: data.ScopedKeyType{
				Scope:   proto.Scope("test"),
				KeyType: proto.KeyType_Ethereum_Secp256k1,
			},
			Address:       crypto.PubkeyToAddress(wallet.PublicKey).Hex(),
			Identity:      &proto.Identity{Type: proto.IdentityType_Email, Subject: subject},
			EncryptedData: encData,
		}
		err = svc.Signers.Put(context.Background(), signer)
		require.NoError(t, err)
	}

	// Rotate the key
	err = c.RotateCipherKey(context.Background(), oldKey.KeyRef)
	require.NoError(t, err)

	// Generate a new key
	newKey, _, err := svc.EncryptionPool.GenerateKey(context.Background(), att, 0)
	require.NoError(t, err)

	done, err := c.RefreshEncryptedData(context.Background(), protoadmin.Table_Signers, oldKey.KeyRef, 50)
	require.NoError(t, err)
	assert.False(t, done) // there is still 50 signers left

	signers, done, err := svc.Signers.ListByCipherKeyRef(context.Background(), oldKey.KeyRef, 100)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Len(t, signers, 50)

	for _, signer := range signers {
		assert.Equal(t, signer.EncryptedData.CipherKeyRef, oldKey.KeyRef)
	}

	signers, done, err = svc.Signers.ListByCipherKeyRef(context.Background(), newKey.KeyRef, 100)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Len(t, signers, 50)

	for _, signer := range signers {
		assert.Equal(t, signer.EncryptedData.CipherKeyRef, newKey.KeyRef)
	}
}

func TestCleanupUnusedCipherKeys(t *testing.T) {
	ep, terminate := initLocalstack()
	defer terminate()
	svc := initRPC(t, ep, nil, func(cfg *config.Config) {
		cfg.Encryption[0].PoolSize = 10
	})

	att, err := svc.Enclave.GetAttestation(context.Background(), nil, nil)
	require.NoError(t, err)
	defer att.Close()

	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()

	c := protoadmin.NewIdentityInstrumentAdminClient(srv.URL, http.DefaultClient)

	keys := make([]*data.CipherKey, 10)
	for i := 0; i < 10; i++ {
		key, _, err := svc.EncryptionPool.GenerateKey(context.Background(), att, -i-1)
		require.NoError(t, err)
		keys[i] = key
	}

	for i := 0; i < 5; i++ {
		err := svc.Signers.Put(context.Background(), &data.Signer{
			ScopedKeyType: data.ScopedKeyType{
				Scope:   proto.Scope("cleanup" + strconv.Itoa(i)),
				KeyType: proto.KeyType_Ethereum_Secp256k1,
			},
			Identity: &proto.Identity{
				Type:    proto.IdentityType_Email,
				Subject: "cleanup" + strconv.Itoa(i) + "@test.com",
			},
			Address: "0x1234567890123456789012345678901234567890",
			EncryptedData: data.EncryptedData[*proto.SignerData]{
				CipherKeyRef:   keys[i].KeyRef,
				Ciphertext:     "test",
				CiphertextHash: crypto.Keccak256([]byte("test")),
			},
		})
		require.NoError(t, err)
	}

	deleted, err := c.CleanupUnusedCipherKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 5, deleted)

	retrievedKeys, _, err := svc.CipherKeys.ListGenerationKeys(context.Background(), 0, nil, nil)
	require.NoError(t, err)
	assert.Len(t, retrievedKeys, 5)
}
