package rpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xsequence/ethkit/ethwallet"
	"github.com/0xsequence/ethkit/go-ethereum/common"
	"github.com/0xsequence/ethkit/go-ethereum/common/hexutil"
	"github.com/0xsequence/ethkit/go-ethereum/crypto"
	ethcrypto "github.com/0xsequence/ethkit/go-ethereum/crypto"
	identityInstrument "github.com/0xsequence/identity-instrument"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/data"
	"github.com/0xsequence/identity-instrument/proto"
	"github.com/0xsequence/identity-instrument/rpc/attestation"
	"github.com/0xsequence/identity-instrument/rpc/auth"
	"github.com/0xsequence/identity-instrument/rpc/auth/email"
	"github.com/0xsequence/identity-instrument/rpc/auth/oidc"
	"github.com/0xsequence/identity-instrument/rpc/awscreds"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog"
	"github.com/go-chi/traceid"
	"github.com/goware/cachestore/memlru"
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
	AuthProviders   map[proto.IdentityType]auth.Provider

	measurements *enclave.Measurements
	startTime    time.Time
	running      int32
}

func New(cfg *config.Config, transport http.RoundTripper) (*RPC, error) {
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	wrappedClient := client // tracing.WrapClient(client)

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
	enc, err := enclave.New(context.Background(), enclaveProvider, kmsClient)
	if err != nil {
		return nil, err
	}

	m, err := enc.GetMeasurements(context.Background())
	if err != nil {
		return nil, err
	}

	authProviders, err := makeAuthProviders(wrappedClient, awsCfg, cfg)
	if err != nil {
		return nil, err
	}

	db := dynamodb.NewFromConfig(awsCfg)
	s := &RPC{
		Log: httplog.NewLogger("waas-authenticator", httplog.Options{
			LogLevel: zerolog.LevelDebugValue,
		}),
		Config:          cfg,
		Server:          httpServer,
		HTTPClient:      wrappedClient,
		Enclave:         enc,
		AuthCommitments: data.NewAuthCommitmentTable(db, cfg.Database.AuthCommitmentsTable, data.AuthCommitmentIndices{}),
		AuthKeys:        data.NewAuthKeyTable(db, cfg.Database.AuthKeysTable, data.AuthKeyIndices{}),
		Signers:         data.NewSignerTable(db, cfg.Database.SignersTable, data.SignerIndices{ByAddress: "Address-Index"}),
		AuthProviders:   authProviders,
		startTime:       time.Now(),
		measurements:    m,
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

	// HTTP request logger
	r.Use(httplog.RequestLogger(s.Log, []string{"/", "/ping", "/status", "/favicon.ico"}))

	// Timeout any request after 28 seconds as Cloudflare has a 30 second limit anyways.
	r.Use(middleware.Timeout(28 * time.Second))

	// Generate attestation document
	r.Use(attestation.Middleware(s.Enclave))

	r.Handle("/rpc/IdentityInstrument/*", proto.NewIdentityInstrumentServer(s))

	return r
}

func (s *RPC) InitiateAuth(ctx context.Context, params *proto.InitiateAuthParams) (string, error) {
	att := attestation.FromContext(ctx)

	if params == nil {
		return "", fmt.Errorf("params is nil")
	}

	authProvider, err := s.getAuthProvider(params.IdentityType)
	if err != nil {
		return "", fmt.Errorf("get auth provider: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := data.AuthID{
		EcosystemID:  params.EcosystemID,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		return "", fmt.Errorf("getting commitment: %w", err)
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
		if err != nil {
			return "", fmt.Errorf("decrypting commitment data: %w", err)
		}
	}

	storeFn := func(ctx context.Context, commitment *proto.AuthCommitmentData) error {
		att := attestation.FromContext(ctx)

		encryptedData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], commitment)
		if err != nil {
			return fmt.Errorf("encrypting commitment: %w", err)
		}

		dbCommitment := &data.AuthCommitment{
			ID: data.AuthID{
				EcosystemID:  commitment.EcosystemID,
				IdentityType: commitment.IdentityType,
				Verifier:     commitment.Verifier,
			},
			EncryptedData: encryptedData,
		}
		if err := s.AuthCommitments.Put(ctx, dbCommitment); err != nil {
			return fmt.Errorf("putting verification context: %w", err)
		}
		return nil
	}

	return authProvider.InitiateAuth(ctx, commitment, params.EcosystemID, params.Verifier, params.AuthKey, storeFn)
}

func (s *RPC) RegisterAuth(ctx context.Context, params *proto.RegisterAuthParams) (string, error) {
	att := attestation.FromContext(ctx)

	authProvider, err := s.getAuthProvider(params.IdentityType)
	if err != nil {
		return "", fmt.Errorf("get auth provider: %w", err)
	}

	var commitment *proto.AuthCommitmentData
	authID := data.AuthID{
		EcosystemID:  params.EcosystemID,
		IdentityType: params.IdentityType,
		Verifier:     params.Verifier,
	}
	dbCommitment, found, err := s.AuthCommitments.Get(ctx, authID)
	if err != nil {
		return "", fmt.Errorf("get commitment: %w", err)
	}
	if found && dbCommitment != nil {
		commitment, err = dbCommitment.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
		if err != nil {
			return "", fmt.Errorf("decrypt commitment data: %w", err)
		}

		// TODO: attempts

		if time.Now().After(commitment.Expiry) {
			return "", fmt.Errorf("commitment expired")
		}

		if !dbCommitment.CorrespondsTo(commitment) {
			return "", fmt.Errorf("commitment mismatch")
		}
	}

	ident, err := authProvider.Verify(ctx, commitment, params.AuthKey, params.Answer)
	if err != nil {
		if commitment != nil {
			// TODO: increment attempt and store it back
		}
		return "", fmt.Errorf("verify answer: %w", err)
	}

	// always use normalized email address
	ident.Email = email.Normalize(ident.Email)

	dbSigner, signerFound, err := s.Signers.GetByIdentity(ctx, params.EcosystemID, ident)
	if err != nil {
		return "", fmt.Errorf("retrieve signer: %w", err)
	}

	if !signerFound {
		signerWallet, err := ethwallet.NewWalletFromRandomEntropy()
		if err != nil {
			return "", fmt.Errorf("generate wallet: %w", err)
		}
		signerData := &proto.SignerData{
			EcosystemID: params.EcosystemID,
			Identity:    &ident,
			PrivateKey:  signerWallet.PrivateKeyHex(),
		}
		encData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], signerData)
		if err != nil {
			return "", fmt.Errorf("encrypt signer data: %w", err)
		}
		dbSigner = &data.Signer{
			EcosystemID:   params.EcosystemID,
			Address:       signerWallet.Address().Hex(),
			Identity:      data.Identity(ident),
			EncryptedData: encData,
		}
		if err := s.Signers.Put(ctx, dbSigner); err != nil {
			return "", fmt.Errorf("put signer: %w", err)
		}
	}

	ttl := 5 * time.Minute
	authKeyData := &proto.AuthKeyData{
		EcosystemID:   params.EcosystemID,
		SignerAddress: dbSigner.Address,
		KeyType:       params.AuthKey.KeyType,
		PublicKey:     params.AuthKey.PublicKey,
		Expiry:        time.Now().Add(ttl),
	}

	encData, err := data.Encrypt(ctx, att, s.Config.KMS.EncryptionKeys[0], authKeyData)
	if err != nil {
		return "", fmt.Errorf("encrypt auth key data: %w", err)
	}

	dbAuthKey := &data.AuthKey{
		EcosystemID:   params.EcosystemID,
		KeyID:         params.AuthKey.String(),
		EncryptedData: encData,
	}
	if err := s.AuthKeys.Put(ctx, dbAuthKey); err != nil {
		return "", fmt.Errorf("put auth key: %w", err)
	}

	return dbSigner.Address, nil
}

func (s *RPC) Sign(ctx context.Context, params *proto.SignParams) (string, error) {
	att := attestation.FromContext(ctx)

	digestBytes := common.FromHex(params.Digest)
	sigBytes := common.FromHex(params.Signature)
	authKeyBytes := common.FromHex(params.AuthKey.PublicKey)

	switch params.AuthKey.KeyType {
	case proto.KeyType_P256K1:
		// Add Ethereum prefix to the hash
		prefixedHash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(params.Digest), params.Digest)))

		// handle recovery byte
		if sigBytes[64] == 27 || sigBytes[64] == 28 {
			sigBytes[64] -= 27
		}

		// Recover the public key from the signature
		pubKey, err := crypto.Ecrecover(prefixedHash.Bytes(), sigBytes)
		if err != nil {
			return "", fmt.Errorf("failed to recover public key: %w", err)
		}
		addr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

		if strings.ToLower(addr.String()) != strings.ToLower(params.AuthKey.PublicKey) {
			return "", fmt.Errorf("invalid signature")
		}

	case proto.KeyType_P256R1:
		x, y := elliptic.Unmarshal(elliptic.P256(), authKeyBytes)
		if x == nil || y == nil {
			return "", fmt.Errorf("invalid public key")
		}

		pub := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:64])
		if !ecdsa.Verify(&pub, digestBytes, r, s) {
			return "", fmt.Errorf("invalid signature")
		}

	default:
		return "", fmt.Errorf("unknown key type")
	}

	dbAuthKey, found, err := s.AuthKeys.Get(ctx, params.EcosystemID, params.AuthKey.String())
	if err != nil {
		return "", fmt.Errorf("get auth key: %w", err)
	}
	if !found {
		return "", fmt.Errorf("auth key not found")
	}

	authKeyData, err := dbAuthKey.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
	if err != nil {
		return "", fmt.Errorf("decrypt auth key data: %w", err)
	}

	if !dbAuthKey.CorrespondsTo(authKeyData) {
		return "", fmt.Errorf("auth key mismatch")
	}

	if authKeyData.Expiry.Before(time.Now()) {
		return "", fmt.Errorf("auth key expired")
	}

	if authKeyData.SignerAddress != params.Signer {
		return "", fmt.Errorf("signer mismatch")
	}

	dbSigner, found, err := s.Signers.GetByAddress(ctx, params.EcosystemID, authKeyData.SignerAddress)
	if err != nil {
		return "", fmt.Errorf("get signer: %w", err)
	}
	if !found {
		return "", fmt.Errorf("signer not found")
	}

	signerData, err := dbSigner.EncryptedData.Decrypt(ctx, att, s.Config.KMS.EncryptionKeys)
	if err != nil {
		return "", fmt.Errorf("decrypt signer data: %w", err)
	}
	signerWallet, err := ethwallet.NewWalletFromPrivateKey(signerData.PrivateKey[2:])
	if err != nil {
		return "", fmt.Errorf("create signer wallet: %w", err)
	}
	if !dbSigner.CorrespondsTo(signerData, signerWallet) {
		return "", fmt.Errorf("signer mismatch")
	}

	sigBytes, err = ethcrypto.Sign(digestBytes, signerWallet.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("sign digest: %w", err)
	}

	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}

	return hexutil.Encode(sigBytes), nil
}

func (s *RPC) getAuthProvider(identityType proto.IdentityType) (auth.Provider, error) {
	if identityType == "" {
		identityType = proto.IdentityType_None
	}

	authProvider, ok := s.AuthProviders[identityType]
	if !ok {
		return nil, fmt.Errorf("unknown identity type: %v", identityType)
	}
	return authProvider, nil
}

func makeAuthProviders(client HTTPClient, awsCfg aws.Config, cfg *config.Config) (map[proto.IdentityType]auth.Provider, error) {
	cacheBackend := memlru.Backend(1024)
	oidcProvider, err := oidc.NewAuthProvider(cacheBackend, client)
	if err != nil {
		return nil, err
	}
	//stytchProvider, err := oidc.NewStytchAuthProvider(cacheBackend, client)
	//if err != nil {
	//	return nil, err
	//}

	// sender := email.NewSESSender(awsCfg, cfg.SES)
	// emailProvider := email.NewAuthProvider(sender, builderClient)
	// guestProvider := guest.NewAuthProvider()

	// playfabProvider := playfab.NewAuthProvider(client)

	providers := map[proto.IdentityType]auth.Provider{
		// proto.IdentityType_None:    auth.NewTracedProvider("oidc.LegacyAuthProvider", legacyVerifier),
		// proto.IdentityType_Email:   auth.NewTracedProvider("email.AuthProvider", emailProvider),
		proto.IdentityType_OIDC: oidcProvider, // auth.NewTracedProvider("oidc.AuthProvider", oidcProvider),
		// proto.IdentityType_Guest:   auth.NewTracedProvider("guest.AuthProvider", guestProvider),
		// proto.IdentityType_PlayFab: auth.NewTracedProvider("playfab.AuthProvider", playfabProvider),
		// proto.IdentityType_Stytch:  auth.NewTracedProvider("oidc.StytchAuthProvider", stytchProvider),
	}
	return providers, nil
}
