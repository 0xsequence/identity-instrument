package awscreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// Provider implements aws.CredentialsProvider.
type Provider struct {
	baseURL string
	client  *imds.Client
}

// NewProvider returns a new Provider using the given HTTPClient.
func NewProvider(httpClient imds.HTTPClient, baseURL string) *Provider {
	client := imds.New(imds.Options{
		HTTPClient:     httpClient,
		Endpoint:       baseURL,
		EnableFallback: aws.FalseTernary, // disable fallback to IMDSv1
	})
	return &Provider{
		baseURL: baseURL,
		client:  client,
	}
}

// Retrieve returns a new set of aws.Credentials.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	cred, err := p.getAWSCredential(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	return *cred, nil
}

func (p *Provider) getAWSCredential(ctx context.Context) (awsCred *aws.Credentials, err error) {
	profileName, err := p.getInstanceProfileName(ctx)
	if err != nil {
		return nil, err
	}

	res, err := p.client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "iam/security-credentials/" + profileName,
	})
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}

	var cred struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.NewDecoder(res.Content).Decode(&cred); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &aws.Credentials{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
		SessionToken:    cred.Token,
		Expires:         time.Now().Add(time.Hour),
		CanExpire:       true,
	}, nil
}

func (p *Provider) getInstanceProfileName(ctx context.Context) (name string, err error) {
	res, err := p.client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "iam/security-credentials/",
	})
	if err != nil {
		return "", fmt.Errorf("getting metadata: %w", err)
	}

	content, err := io.ReadAll(res.Content)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return string(content), nil
}
