package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/mdlayher/vsock"
)

var (
	vsockCID      uint32
	targetPort    uint32
	targetHost    string
	listenAddress string
)

func main() {
	if s := os.Getenv("VSOCK_CID"); s != "" {
		i, _ := strconv.Atoi(s)
		vsockCID = uint32(i)
	}
	if s := os.Getenv("TARGET_PORT"); s != "" {
		i, _ := strconv.Atoi(s)
		targetPort = uint32(i)
	}
	targetHost = os.Getenv("TARGET_HOST")
	listenAddress = os.Getenv("LISTEN_ADDRESS")

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			if vsockCID != 0 {
				return vsock.Dial(vsockCID, targetPort, &vsock.Config{})
			}

			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, "tcp", targetHost+":"+strconv.Itoa(int(targetPort)))
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: transport}

	log.Println("Listening on " + listenAddress)
	http.ListenAndServe(listenAddress, handler(client))
}

func handler(client *http.Client) http.Handler {
	r := chi.NewRouter()

	// CORS
	corsOptions := cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool { return true },
		AllowedMethods:  []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{
			"Accept", "Authorization", "Content-Type", "X-Access-Key", "X-Attestation-Nonce", "Accept-Signature", "Webrpc",
		},
		AllowCredentials: true,
		ExposedHeaders: []string{
			"Date", "Signature", "Signature-Input", "Content-Digest",
			"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
			"Webrpc",
		},
		MaxAge: 600,
	}
	r.Use(cors.New(corsOptions).Handler)

	r.Handle("/*", proxy(client))

	return r
}

func proxy(httpClient *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := "http://" + r.Host + r.URL.String()
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		clientReq, err := http.NewRequest(r.Method, url, bytes.NewBuffer(reqBody))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		copyHeader(clientReq.Header, r.Header)

		clientReq.Header.Set("X-Sequence-Ecosystem", os.Getenv("SEQUENCE_ECOSYSTEM"))

		res, err := httpClient.Do(clientReq.WithContext(r.Context()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer res.Body.Close()

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		res.Body = io.NopCloser(bytes.NewBuffer(resBody))

		copyHeader(w.Header(), res.Header)
		w.WriteHeader(res.StatusCode)
		w.Write(resBody)
	})
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		if strings.HasPrefix(strings.ToLower(k), "x-sequence-") {
			continue
		}

		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
