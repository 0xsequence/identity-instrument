package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/wait"
)

var awsEndpoint string

func TestMain(m *testing.M) {
	ep, terminate := initLocalstack()
	defer terminate()
	awsEndpoint = ep
	code := m.Run()
	os.Exit(code)
}

func initRPC(t *testing.T, transport http.RoundTripper, options ...func(*config.Config)) *rpc.RPC {
	cfg := initConfig(t, awsEndpoint)
	for _, opt := range options {
		opt(cfg)
	}

	svc, err := rpc.New(cfg, transport)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func initConfig(t *testing.T, awsEndpoint string) *config.Config {
	return &config.Config{
		Region: "us-east-1",
		Database: config.DatabaseConfig{
			AuthCommitmentsTable: "AuthCommitmentsTable",
			AuthKeysTable:        "AuthKeysTable",
			SignersTable:         "SignersTable",
			CipherKeysTable:      "CipherKeysTable",
		},
		Endpoints: config.EndpointsConfig{
			AWSEndpoint: awsEndpoint,
		},
		SES: config.SESConfig{
			Source: "noreply@local.auth.sequence.app",
		},
		Builder: config.BuilderConfig{
			SecretID: "BuilderJWT",
		},
		Encryption: []config.EncryptionConfig{
			{
				PoolSize:  10,
				Threshold: 2,
				KMSKeys: []string{
					"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79",
					"arn:aws:kms:us-east-1:000000000000:key/aeb99e0f-9e89-44de-a084-e1817af47778",
				},
			},
		},
	}
}

func initLocalstack() (string, func()) {
	ctx := context.Background()
	lc, err := localstack.RunContainer(context.Background(),
		testcontainers.WithImage("localstack/localstack:3.4"),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				WaitingFor: wait.ForAll(
					wait.ForHTTP("/_localstack/health").WithPort("4566/tcp"),
					wait.ForLog("Finished bootstrapping localstack resources!"),
				).WithDeadline(60 * time.Second),
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      "../docker/awslocal_ready_hook.sh",
						ContainerFilePath: "/etc/localstack/init/ready.d/awslocal_ready_hook.sh",
						FileMode:          0777,
					},
				},
			},
		}),
	)
	if err != nil {
		panic(err)
	}
	terminate := func() {
		lc.Terminate(context.Background())
	}

	mappedPort, err := lc.MappedPort(ctx, "4566/tcp")
	if err != nil {
		terminate()
		panic(err)
	}

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		terminate()
		panic(err)
	}
	defer provider.Close()

	host, err := provider.DaemonHost(ctx)
	if err != nil {
		terminate()
		panic(err)
	}

	endpoint := fmt.Sprintf("http://%s:%d", host, mappedPort.Int())
	return endpoint, terminate
}

func getSentEmailMessage(t *testing.T, recipient string) (string, string, bool) {
	res, err := http.Get(fmt.Sprintf("%s/_aws/ses?email=noreply@local.auth.sequence.app", awsEndpoint))
	require.NoError(t, err)
	defer res.Body.Close()

	var result struct {
		Messages []struct {
			Destination struct {
				ToAddresses []string
			}
			Subject string
			Body    struct {
				HTML string `json:"html_part"`
			}
		}
	}

	require.NoError(t, json.NewDecoder(res.Body).Decode(&result))

	for _, msg := range result.Messages {
		for _, toAddress := range msg.Destination.ToAddresses {
			if toAddress == recipient {
				return msg.Subject, msg.Body.HTML, true
			}
		}
	}

	return "", "", false
}

func deriveKey(t *testing.T, source string) *ecdsa.PrivateKey {
	key := sha256.Sum256([]byte(source))
	signer, err := crypto.ToECDSA(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func insertSigner(t *testing.T, svc *rpc.RPC, ecosystem string, identity string, source string) proto.Key {
	ctx := context.Background()
	att, err := svc.Enclave.GetAttestation(ctx, nil, nil)
	require.NoError(t, err)

	signer := deriveKey(t, source)

	var ident proto.Identity
	require.NoError(t, ident.FromString(identity))

	signerData := &proto.SignerData{
		Scope:      proto.Scope("@" + ecosystem),
		KeyType:    proto.KeyType_Secp256k1,
		Identity:   &ident,
		PrivateKey: hexutil.Encode(crypto.FromECDSA(signer)),
	}
	encData, err := data.Encrypt(ctx, att, svc.EncryptionPool, signerData)
	if err != nil {
		t.Fatal(err)
	}
	dbSigner := &data.Signer{
		Address:  crypto.PubkeyToAddress(signer.PublicKey).Hex(),
		Identity: &ident,
		ScopedKeyType: data.ScopedKeyType{
			Scope:   proto.Scope("@" + ecosystem),
			KeyType: proto.KeyType_Secp256k1,
		},
		EncryptedData: encData,
	}
	if err := svc.Signers.Put(ctx, dbSigner); err != nil {
		t.Fatal(err)
	}
	return proto.Key{
		KeyType: proto.KeyType_Secp256k1,
		Address: crypto.PubkeyToAddress(signer.PublicKey).Hex(),
	}
}

func signRequest(t *testing.T, authKey *ecdsa.PrivateKey, params any) string {
	jsonParams, err := json.Marshal(params)
	require.NoError(t, err)

	digest := crypto.Keccak256(jsonParams)
	digestHex := hexutil.Encode(digest)
	prefixedHash := crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(digestHex), digestHex)))
	sig, err := crypto.Sign(prefixedHash, authKey)
	require.NoError(t, err)

	return hexutil.Encode(sig)
}
