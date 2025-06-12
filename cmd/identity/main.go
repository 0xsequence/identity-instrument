package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	identityInstrument "github.com/0xsequence/identity-instrument"
	"github.com/0xsequence/identity-instrument/config"
	"github.com/0xsequence/identity-instrument/rpc"
	"github.com/go-chi/traceid"
	"github.com/go-chi/transport"
	"github.com/mdlayher/vsock"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		panic(err)
	}

	baseTransport := http.DefaultTransport
	if cfg.Service.VSock || cfg.Service.ProxyHost != "" {
		baseTransport = &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse("http://vsock-proxy")
			},
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				if cfg.Service.VSock {
					log.Printf("Outgoing connection to %s://%s\n", network, addr)
					return vsock.Dial(3, cfg.Service.ProxyPort, nil)
				}
				return net.Dial(network, cfg.Service.ProxyHost+":"+strconv.Itoa(int(cfg.Service.ProxyPort)))
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// HTTP transport chain to use for all outgoing connections out of the enclave
	transportChain := transport.Chain(
		baseTransport,
		transport.SetHeader("User-Agent", "identity-instrument/"+identityInstrument.VERSION),
		traceid.Transport,
	)

	s, err := rpc.New(cfg, transportChain)
	if err != nil {
		panic(err)
	}
	defer s.Stop(context.Background())

	// Listen on a VSOCK if enabled
	var l net.Listener
	if cfg.Service.VSock {
		l, err = vsock.Listen(cfg.Service.EnclavePort, nil)
	} else {
		l, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.EnclavePort))
	}
	if err != nil {
		panic(err)
	}

	if err := s.Run(context.Background(), l); err != nil {
		panic(err)
	}
}
