package o11y

import (
	"context"
	"net/http"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
}

type wrappedClient struct {
	HTTPClient
	ctx context.Context
}

func WrapClient(c HTTPClient) HTTPClient {
	return &wrappedClient{HTTPClient: c}
}

func WrapClientWithContext(ctx context.Context, c HTTPClient) HTTPClient {
	return &wrappedClient{HTTPClient: c, ctx: ctx}
}

func (c *wrappedClient) Do(req *http.Request) (res *http.Response, err error) {
	ctx, span := Trace(req.Context(), req.URL.Host, WithSpanKind(SpanKindClient))
	defer func() {
		if err != nil {
			span.RecordError(err)
		} else {
			span.SetMetadata(map[string]any{
				"http.status_code":             res.StatusCode,
				"http.response_content_length": res.ContentLength,
			})
			span.SetStatus(res.StatusCode)
		}
		span.End()
	}()

	span.SetMetadata(map[string]any{
		"http.method":                 req.Method,
		"http.url":                    req.URL.String(),
		"http.scheme":                 req.URL.Scheme,
		"http.query":                  req.URL.RawQuery,
		"http.path":                   req.URL.Path,
		"http.request_content_length": req.ContentLength,
	})

	return c.HTTPClient.Do(req.WithContext(ctx))
}

func (c *wrappedClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if c.ctx != nil {
		req = req.WithContext(c.ctx)
	}

	return c.Do(req)
}
