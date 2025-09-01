package main

import (
	"net/http"

	"github.com/0xsequence/identity-instrument/proto/builder"
)

func main() {
	svc := builder.NewEcosystemManagerServer(builder.NewMock())
	http.ListenAndServe(":9999", svc)
}
