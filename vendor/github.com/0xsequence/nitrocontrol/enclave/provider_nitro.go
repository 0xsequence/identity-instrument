package enclave

import (
	"context"

	"github.com/0xsequence/nsm"
	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
)

type nitroSession struct {
	*nsm.Session
}

func (s *nitroSession) Send(ctx context.Context, req request.Request) (response.Response, error) {
	return s.Session.Send(req)
}

func NitroProvider() (Session, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, err
	}
	return &nitroSession{Session: sess}, nil
}
