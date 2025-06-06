package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	identityInstrument "github.com/0xsequence/identity-instrument"
	"github.com/0xsequence/identity-instrument/auth"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/encryption"
	"github.com/0xsequence/identity-instrument/o11y"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/awscreds"
	"github.com/0xsequence/identity-instrument/rpc/internal/attestation"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog"
	"github.com/go-chi/traceid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type RPC struct {
	Config          *config.Config
	Log             zerolog.Logger
	Server          *http.Server
	HTTPClient      HTTPClient
	Enclave         *enclave.Enclave
	AuthKeys        *data.AuthKeyTable
	AuthCommitments *data.AuthCommitmentTable
	Signers         *data.SignerTable
	AuthHandlers    map[proto.AuthMode]auth.Handler
	Secrets         *secretsmanager.Client
	EncryptionPool  *encryption.Pool

	measurements enclave.Measurements
	startTime    time.Time
	running      int32
}

func New(cfg *config.Config, transport http.RoundTripper) (*RPC, error) {
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	wrappedClient := o11y.WrapClient(client)

	options := []func(options *awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(wrappedClient),
		awsconfig.WithCredentialsProvider(awscreds.NewProvider(wrappedClient, cfg.Endpoints.MetadataServer)),
	}

	if cfg.Endpoints.AWSEndpoint != "" {
		options = append(options, awsconfig.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: cfg.Endpoints.AWSEndpoint}, nil
			}),
		), awsconfig.WithCredentialsProvider(&awscreds.StaticProvider{
			AccessKeyID:     "test",
			SecretAccessKey: "test",
			SessionToken:    "test",
		}))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), options...)
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       45 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	kmsClient := kms.NewFromConfig(awsCfg)
	enclaveProvider := enclave.DummyProvider
	if cfg.Service.UseNSM {
		enclaveProvider = enclave.NitroProvider
	}
	enc, err := enclave.New(context.Background(), o11y.WrapEnclaveProvider(enclaveProvider), kmsClient)
	if err != nil {
		return nil, err
	}

	db := dynamodb.NewFromConfig(awsCfg)
	cipherKeyTable := data.NewCipherKeyTable(db, cfg.Database.CipherKeysTable, data.CipherKeyIndices{
		KeyRefIndex: "KeyRef-Index",
	})
	encPoolConfigs := make([]*encryption.Config, len(cfg.Encryption))
	for i, encCfg := range cfg.Encryption {
		cryptors := make([]encryption.Cryptor, len(encCfg.KMSKeys))
		for j, kmsKey := range encCfg.KMSKeys {
			cryptors[j] = encryption.NewKMSKey(kmsKey)
		}
		encPoolConfigs[i] = encryption.NewConfig(encCfg.PoolSize, encCfg.Threshold, cryptors)
	}

	encPool := encryption.NewPool(enc, encPoolConfigs, cipherKeyTable)

	m, err := enc.GetMeasurements(context.Background(), []uint16{0})
	if err != nil {
		return nil, err
	}

	s := &RPC{
		Log: httplog.NewLogger("identity-instrument", httplog.Options{
			LogLevel: zerolog.LevelDebugValue,
		}),
		Config:          cfg,
		Server:          httpServer,
		HTTPClient:      wrappedClient,
		Enclave:         enc,
		AuthCommitments: data.NewAuthCommitmentTable(db, cfg.Database.AuthCommitmentsTable, data.AuthCommitmentIndices{}),
		AuthKeys:        data.NewAuthKeyTable(db, cfg.Database.AuthKeysTable, data.AuthKeyIndices{}),
		Signers:         data.NewSignerTable(db, cfg.Database.SignersTable, data.SignerIndices{ByAddress: "Address-Index"}),
		Secrets:         secretsmanager.NewFromConfig(awsCfg),
		EncryptionPool:  encPool,
		startTime:       time.Now(),
		measurements:    m,
	}

	s.AuthHandlers, err = s.makeAuthHandlers(awsCfg, *cfg)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *RPC) Run(ctx context.Context, l net.Listener) error {
	if s.IsRunning() {
		return fmt.Errorf("rpc: already running")
	}

	s.Log.Info().
		Str("op", "run").
		Str("ver", identityInstrument.VERSION).
		Msgf("-> rpc: started enclave")

	atomic.StoreInt32(&s.running, 1)
	defer atomic.StoreInt32(&s.running, 0)

	// Setup HTTP server handler
	s.Server.Handler = s.Handler()

	// Handle stop signal to ensure clean shutdown
	go func() {
		<-ctx.Done()
		s.Stop(context.Background())
	}()

	// Start the http server and serve!
	err := s.Server.Serve(l)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *RPC) Stop(timeoutCtx context.Context) {
	if !s.IsRunning() || s.IsStopping() {
		return
	}
	atomic.StoreInt32(&s.running, 2)

	s.Log.Info().Str("op", "stop").Msg("-> rpc: stopping..")
	s.Server.Shutdown(timeoutCtx)
	s.Log.Info().Str("op", "stop").Msg("-> rpc: stopped.")
}

func (s *RPC) IsRunning() bool {
	return atomic.LoadInt32(&s.running) == 1
}

func (s *RPC) IsStopping() bool {
	return atomic.LoadInt32(&s.running) == 2
}

func (s *RPC) Handler() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)

	// Propagate TraceId
	r.Use(traceid.Middleware)

	// Timeout any request after 28 seconds as Cloudflare has a 30 second limit anyways.
	r.Use(middleware.Timeout(28 * time.Second))

	r.Handle("/metrics", promhttp.Handler())

	r.Group(func(r chi.Router) {
		// Observability middleware
		r.Use(o11y.Middleware())

		// Generate attestation document
		r.Use(attestation.Middleware(s.Enclave))

		// Healthcheck
		r.Handle("/health", http.HandlerFunc(s.healthHandler))
		r.Handle("/status", http.HandlerFunc(s.statusHandler))
	})

	r.Group(func(r chi.Router) {
		// Observability middleware
		r.Use(o11y.Middleware())

		// Generate attestation document
		r.Use(attestation.Middleware(s.Enclave))

		srv := proto.NewIdentityInstrumentServer(s)
		r.Handle("/rpc/IdentityInstrument/CommitVerifier", srv)
		r.Handle("/rpc/IdentityInstrument/CompleteAuth", srv)
		r.Handle("/rpc/IdentityInstrument/Sign", srv)
	})

	return r
}

func (s *RPC) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"startTime": s.startTime,
		"uptime":    uint64(time.Now().UTC().Sub(s.startTime).Seconds()),
		"ver":       identityInstrument.VERSION,
		"pcr0":      s.measurements[0],
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (s *RPC) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	att := attestation.FromContext(ctx)
	for _, kmsKey := range s.Config.Encryption[0].KMSKeys {
		if _, err := att.GenerateDataKey(ctx, kmsKey); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

type scopedParams interface {
	GetScope() proto.Scope
}

func (s *RPC) getScope(ctx context.Context, params scopedParams) (proto.Scope, error) {
	scope := params.GetScope()
	if scope.IsValid() {
		return scope, nil
	}

	r := ctx.Value(proto.HTTPRequestCtxKey)
	if r == nil {
		return "", fmt.Errorf("missing http request")
	}

	scope = proto.Scope(r.(*http.Request).Header.Get("X-Sequence-Scope"))
	if !scope.IsValid() {
		return "", fmt.Errorf("invalid X-Sequence-Scope header")
	}

	return scope, nil
}
