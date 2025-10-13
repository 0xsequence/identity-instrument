package awscreds_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/identity-instrument/rpc/awscreds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_Retrieve(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			assert.Equal(t, "PUT", r.Method)

			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "3600")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("TOKEN"))

		case "/latest/meta-data/iam/security-credentials/":
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "TOKEN", r.Header.Get("X-Aws-Ec2-Metadata-Token"))

			w.WriteHeader(200)
			_, _ = w.Write([]byte("PROFILE"))

		case "/latest/meta-data/iam/security-credentials/PROFILE":
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "TOKEN", r.Header.Get("X-Aws-Ec2-Metadata-Token"))

			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"AccessKeyId":"AccessKeyID","SecretAccessKey":"SecretAccessKey","Token":"SessionToken"}`))

		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte("Wrong path"))
		}
	}))

	provider := awscreds.NewProvider(http.DefaultClient, server.URL)
	creds, err := provider.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AccessKeyID", creds.AccessKeyID)
	assert.Equal(t, "SecretAccessKey", creds.SecretAccessKey)
	assert.Equal(t, "SessionToken", creds.SessionToken)
}
