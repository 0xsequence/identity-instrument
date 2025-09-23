package encryption_test

import (
	"context"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockKMS struct {
	mock.Mock
}

func (m *MockKMS) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	args := m.Called(ctx, params, optFns)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*kms.DecryptOutput), args.Error(1)
}

func (m *MockKMS) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	args := m.Called(ctx, params, optFns)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*kms.GenerateDataKeyOutput), args.Error(1)
}

type MockKeysTable struct {
	mock.Mock
}

func (m *MockKeysTable) Get(ctx context.Context, generation int, keyIndex int, consistentRead bool) (*data.CipherKey, bool, error) {
	args := m.Called(ctx, generation, keyIndex, consistentRead)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*data.CipherKey), args.Bool(1), args.Error(2)
}

func (m *MockKeysTable) GetLatestByKeyRef(ctx context.Context, keyRef string, consistentRead bool) (*data.CipherKey, bool, error) {
	args := m.Called(ctx, keyRef, consistentRead)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*data.CipherKey), args.Bool(1), args.Error(2)
}

func (m *MockKeysTable) Create(ctx context.Context, key *data.CipherKey) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockKeysTable) UpdateKeyIndex(ctx context.Context, keyRef string, generation int, newKeyIndex int, attestation []byte) error {
	args := m.Called(ctx, keyRef, generation, newKeyIndex, attestation)
	return args.Error(0)
}

func (m *MockKeysTable) Delete(ctx context.Context, keyRef string, generation int) error {
	args := m.Called(ctx, keyRef, generation)
	return args.Error(0)
}

func (m *MockKeysTable) ListGenerationKeys(ctx context.Context, generation int, active *bool, cursor *int) ([]*data.CipherKey, *int, error) {
	args := m.Called(ctx, generation, active, cursor)
	if args.Get(0) == nil {
		return nil, args.Get(1).(*int), args.Error(2)
	}
	return args.Get(0).([]*data.CipherKey), args.Get(1).(*int), args.Error(2)
}

type MockEncryptedDataTable struct {
	mock.Mock
}

func (m *MockEncryptedDataTable) TableARN() string {
	return m.Called().String(0)
}

func (m *MockEncryptedDataTable) ReferencesCipherKeyRef(ctx context.Context, keyRef string) (bool, error) {
	args := m.Called(ctx, keyRef)
	return args.Bool(0), args.Error(1)
}

type MockRemoteKey struct {
	mock.Mock
}

func (m *MockRemoteKey) RemoteKeyID() string {
	return m.Called().String(0)
}

func (m *MockRemoteKey) Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte) (string, error) {
	args := m.Called(ctx, att, plaintext)
	if args.Get(0) == "" {
		return "", args.Error(1)
	}
	return args.String(0), args.Error(1)
}

func (m *MockRemoteKey) Decrypt(ctx context.Context, att *enclave.Attestation, ciphertext string) ([]byte, error) {
	args := m.Called(ctx, att, ciphertext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

type constantReader struct {
	value byte
}

func (r *constantReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.value
	}
	return len(p), nil
}

func newCipherKey(t *testing.T, enc *enclave.Enclave, options ...func(*data.CipherKey)) (*data.CipherKey, []byte) {
	key := &data.CipherKey{
		Generation: 0,
		KeyIndex:   4,
		KeyRef:     "cipherKey4",
		EncryptedShares: map[string]string{
			"remoteKey1": "encryptedShare1",
			"remoteKey2": "encryptedShare2",
		},
		CreatedAt: time.Now(),
	}

	for _, option := range options {
		option(key)
	}

	hash, err := key.Hash()
	require.NoError(t, err)

	att, err := enc.GetAttestation(context.Background(), nil, hash)
	require.NoError(t, err)
	defer att.Close()

	key.Attestation = att.Document()

	privateKey := [32]byte{}
	for i := range privateKey {
		privateKey[i] = 0x55 // different from the mocked source of randomness
	}

	return key, privateKey[:]
}
