package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/rpc"
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
