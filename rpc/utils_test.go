package rpc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/rpc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
		},
		KMS: config.KMSConfig{
			EncryptionKeys: []string{"arn:aws:kms:us-east-1:000000000000:key/27ebbde0-49d2-4cb6-ad78-4f2c24fe7b79"},
		},
		Endpoints: config.EndpointsConfig{
			AWSEndpoint: awsEndpoint,
		},
		SES: config.SESConfig{
			Source: "noreply@local.auth.sequence.app",
		},
	}
}

func issueAccessTokenAndRunJwksServer(t *testing.T, optTokenBuilderFn ...func(*jwt.Builder, string)) (iss string, tok string, close func()) {
	jwtKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtKey, err := jwk.FromRaw(jwtKeyRaw)
	require.NoError(t, err)
	require.NoError(t, jwtKey.Set(jwk.KeyIDKey, "key-id"))
	jwtPubKey, err := jwtKey.PublicKey()
	require.NoError(t, err)
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(jwtPubKey))

	var uri string
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			openidConfig := map[string]any{"jwks_uri": uri}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(openidConfig))
			return
		}

		m, err := jwtPubKey.AsMap(r.Context())
		m["alg"] = "RS256"
		require.NoError(t, err)
		pkd := map[string]any{"keys": []any{m}}

		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(pkd))
	}))
	uri = jwksServer.URL

	tokBuilder := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Audience([]string{"audience"}).
		Subject("subject")

	if len(optTokenBuilderFn) > 0 && optTokenBuilderFn[0] != nil {
		optTokenBuilderFn[0](tokBuilder, jwksServer.URL)
	}

	tokRaw, err := tokBuilder.Build()
	require.NoError(t, err)
	tokBytes, err := jwt.Sign(tokRaw, jwt.WithKey(jwa.RS256, jwtKey))
	require.NoError(t, err)

	return jwksServer.URL, string(tokBytes), jwksServer.Close
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
