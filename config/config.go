package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Mode      Mode            `toml:"-"`
	Region    string          `toml:"region"`
	Service   ServiceConfig   `toml:"service"`
	KMS       KMSConfig       `toml:"kms"`
	Endpoints EndpointsConfig `toml:"endpoints"`
	SES       SESConfig       `toml:"ses"`
	Database  DatabaseConfig  `toml:"database"`
}

type ServiceConfig struct {
	Mode          string `toml:"mode"`
	VSock         bool   `toml:"vsock"`
	UseNSM        bool   `toml:"use_nsm"`
	EnclavePort   uint32 `toml:"enclave_port"`
	ProxyPort     uint32 `toml:"proxy_port"`
	DebugProfiler bool   `toml:"debug_profiler"`
}

type KMSConfig struct {
	EncryptionKeys []string `toml:"encryption_keys"`
}

type EndpointsConfig struct {
	AWSEndpoint    string `toml:"aws_endpoint"`
	MetadataServer string `toml:"metadata_server"`
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
