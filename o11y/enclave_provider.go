package o11y

import (
	"context"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
)

func WrapEnclaveProvider(provider enclave.Provider) enclave.Provider {
	return func() (enclave.Session, error) {
		sess, err := provider()
		if err != nil {
			return nil, err
		}
		return &wrappedSession{Session: sess}, nil
	}
}

type wrappedSession struct {
	enclave.Session
}

func (w *wrappedSession) Send(ctx context.Context, req request.Request) (res response.Response, err error) {
	ctx, span := Trace(ctx, w.getSpanName(req))
	defer func() {
		span.RecordError(err)
		span.End()
	}()
	return w.Session.Send(ctx, req)
}

func (*wrappedSession) getSpanName(req request.Request) string {
	switch req.(type) {
	case *request.DescribePCR:
		return "NSM.DescribePCR"
	case *request.ExtendPCR:
		return "NSM.ExtendPCR"
	case *request.LockPCR:
		return "NSM.LockPCR"
	case *request.LockPCRs:
		return "NSM.LockPCRs"
	case *request.DescribeNSM:
		return "NSM.DescribeNSM"
	case *request.Attestation:
		return "NSM.Attestation"
	case *request.GetRandom:
		return "NSM.GetRandom"
	}
	return "NSM.Send"
}
