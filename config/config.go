package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Mode       Mode               `toml:"-"`
	Region     string             `toml:"region"`
	Service    ServiceConfig      `toml:"service"`
	Endpoints  EndpointsConfig    `toml:"endpoints"`
	Builder    BuilderConfig      `toml:"builder"`
	SES        SESConfig          `toml:"ses"`
	Database   DatabaseConfig     `toml:"database"`
	Encryption []EncryptionConfig `toml:"encryption"`
}

type ServiceConfig struct {
	Mode          string `toml:"mode"`
	VSock         bool   `toml:"vsock"`
	UseNSM        bool   `toml:"use_nsm"`
	EnclavePort   uint32 `toml:"enclave_port"`
	ProxyHost     string `toml:"proxy_host"`
	ProxyPort     uint32 `toml:"proxy_port"`
	DebugProfiler bool   `toml:"debug_profiler"`
}

type EndpointsConfig struct {
	AWSEndpoint    string `toml:"aws_endpoint"`
	MetadataServer string `toml:"metadata_server"`
}

type BuilderConfig struct {
	BaseURL  string `toml:"base_url"`
	SecretID string `toml:"secret_id"`
}

type SESConfig struct {
	Region        string `toml:"region"`
	Source        string `toml:"source"`
	SourceARN     string `toml:"source_arn"`
	AccessRoleARN string `toml:"access_role_arn"`
}

type DatabaseConfig struct {
	AuthCommitmentsTable string `toml:"auth_commitments_table"`
	AuthKeysTable        string `toml:"auth_keys_table"`
	SignersTable         string `toml:"signers_table"`
	CipherKeysTable      string `toml:"cipher_keys_table"`
}

type EncryptionConfig struct {
	PoolSize  int      `toml:"pool_size"`
	Threshold int      `toml:"threshold"`
	KMSKeys   []string `toml:"kms_keys"`
}

func New() (*Config, error) {
	fileName := os.Getenv("CONFIG")
	var cfg Config
	if _, err := toml.DecodeFile(fileName, &cfg); err != nil {
		return nil, err
	}

	var mode Mode
	switch cfg.Service.Mode {
	case "local":
		mode = LocalMode
	case "dev", "development":
		mode = DevelopmentMode
	case "prod", "production":
		mode = ProductionMode
	default:
		return nil, fmt.Errorf("config service.mode value is invalid, must be one of \"development\", \"dev\", \"production\" or \"prod\"")
	}
	cfg.Mode = mode
	cfg.Service.Mode = mode.String()

	return &cfg, nil
}

type Mode uint32

const (
	LocalMode Mode = iota
	DevelopmentMode
	ProductionMode
)

func (m Mode) String() string {
	switch m {
	case LocalMode:
		return "local"
	case DevelopmentMode:
		return "development"
	case ProductionMode:
		return "production"
	default:
		return ""
	}
}
