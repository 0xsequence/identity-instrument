package enclave

import (
	"context"
	"io"

	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type Provider func() (Session, error)

type Session interface {
	io.ReadCloser
	Send(ctx context.Context, request request.Request) (response.Response, error)
}

type KMS interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}
