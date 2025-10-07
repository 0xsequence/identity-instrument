package main

import (
	"log"
	"net/http"

	"github.com/0xsequence/identity-instrument/proto/builder"
)

func main() {
	svc := builder.NewEcosystemManagerServer(builder.NewMock())
	if err := http.ListenAndServe(":9999", svc); err != nil {
		log.Fatal(err)
	}
}
