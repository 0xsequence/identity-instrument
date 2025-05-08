package enclave

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
	"github.com/fxamacker/cbor/v2"
)

var dummyPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAujDWnWEKVYoHUwieLegkzR2K+4z2Fg3uVEwmZ16iRJiYm5TO
ltLN6BSHaLCqreA1bYXXTFlIG10z2+h16fhkCNKzy4yKwjwUdXJlbBivypQers8h
Pwy1l4c+uID/VX5zXG4y7g7aNc0Ude+lzBvydh9vFz5PwupFzY6ok3czI95ODni7
hn/X/8TBGTyh0eYZu8ehfKy6W9AHbX7D+yL2qebSWWkJBEribptpCcaJi8QPUx9M
HWz8j1j83+M6rnG1FQpLl8VNOO6BXmzb5FNr+6lwEfvwHbht0Azhk0ArMQZ/r0lO
ObAvVDmE2AuudXyWWh5sRrXnXlVitDjTQybQAQIDAQABAoIBAQCYf9Poh0jdkvY4
zkAwvYkW73GcY3JT0gk4xj5WQC6MHKgyFgm3guXfhqD54GmLjK52DD+xaxciQo5t
OdMKVcYpa9qTh4NHX8oqAA6OIRIqzHLtHv3OFGzPtZhrqkx4C+AU/rV8QnH7ywNN
LYIQ0XsfwNNOqFzP+u49VPFCB0m9v7r7mJxeUXp8PDfdhquFT69hpKwNdpzuIDA7
kVOG4ATkkPTGp3AmJj9Vrit9ffi+xlbhrNIuBui9Fxo1v5G6VT2uBhXJU22zl1hS
uYWT4rCOwVQaV/TBDj4T8diDxYpnAXvpO8U+WdqLddhUNaYeDym/HPq2cFsN9VdY
9FYiVl4ZAoGBAOWVsrRAWgFTmx99nUwy6XhobSWgZDrCQiSK50VGzblBdVnmMvyW
Q3LmdqtVQUkZLETx7PZXYkvIzMRP4oWGcViBPaSZ/IqX/kF5WJeXWW7Zgl5HEXTk
GaN26xl7yFjQ5l0f++HAwSW485B2GXvMcdp+6n7OfG6Xo1cg8CgWck5TAoGBAM+c
/h03pASGVvUDNNfeDulyxcXR/PZZTt1YMTqeYLmkbkJcIJVa2uTdDmzcEbGDA0eq
ezMDA+omGB+WR7HRe9+vgmz7Ww4BZRhKjvnxRgHlTGYHBsHhYr21fgPteGv/aDi2
xhAGqyOj1jua8ooqpw8TviYXk6ZbxMNF7eV9KxXbAoGAasEjKaHKuFcyCICWhfoe
ifi02AwuzwvJSci1JYd43a3MbZMXHlCY6HK1t5GbG+xyo1SDRUD42hhy7s3enQwY
5HikO0fHIILwnW1ZfpPH6D2H22LcgSgXq+T+CQl/7ZyloaPfsee5aFsKFqBz1RcJ
0fm1/GTzg1FLiJYuVdWqLTUCgYAaOURHwH1xLN7S9+K22Y+coSimAg4nt8QkZT1i
oBqrmD9tFmHvO5imi92Elo+NknTZmokROnJGIyWs57iKl2FEMdERnvYzYK26UcCZ
hYZIOwRZZs3Ns4BbYg9Ww6oQSiSJ9VwzLgRz7f/ja4DzPsv3NZExEo1N2A2UdMLF
1/eXPQKBgQDSCJ1tWQYVLvjrzJBC5gute7kHf1AhMoIEqpsEvk51JXu7+xN8BMnb
zSwIPR3fSngqLJqGw+Tz5LT3iSsDNVj7EnaHoYvTrxsd2yFYtVmz2fHgnHXBjZmj
AzDn4G6VZ+F11K/sdfuo+1vfgxPendYDkjp0ZtgJc97iBq49Devv1A==
-----END RSA PRIVATE KEY-----`
var dummyCert = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIBATANBgkqhkiG9w0BAQsFADAyMREwDwYDVQQKEwhTZXF1
ZW5jZTEdMBsGA1UEAxMUZHVtbXkubml0cm8tZW5jbGF2ZXMwHhcNMjUwNDI0MTM0
NjA5WhcNMzUwNDI0MTM0NjA5WjAyMREwDwYDVQQKEwhTZXF1ZW5jZTEdMBsGA1UE
AxMUZHVtbXkubml0cm8tZW5jbGF2ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC6MNadYQpVigdTCJ4t6CTNHYr7jPYWDe5UTCZnXqJEmJiblM6W0s3o
FIdosKqt4DVthddMWUgbXTPb6HXp+GQI0rPLjIrCPBR1cmVsGK/KlB6uzyE/DLWX
hz64gP9VfnNcbjLuDto1zRR176XMG/J2H28XPk/C6kXNjqiTdzMj3k4OeLuGf9f/
xMEZPKHR5hm7x6F8rLpb0AdtfsP7Ivap5tJZaQkESuJum2kJxomLxA9TH0wdbPyP
WPzf4zqucbUVCkuXxU047oFebNvkU2v7qXAR+/AduG3QDOGTQCsxBn+vSU45sC9U
OYTYC651fJZaHmxGtedeVWK0ONNDJtABAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIB
hjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSw2hfihIyfiqyiuiuTp3OCt0Sl
8DANBgkqhkiG9w0BAQsFAAOCAQEAl55+EnYlS5/YTQQhZozA/XW7Y9Kt00w9k0Ix
9vXTVeZdzTNR/YKCAzG7ynNjNbdFkhJcqqwKycVOSID0Xz4dWvB6jVukIV6B3W2u
ta/P4SYg4VQ9YzPqF1n1sUzX3OwKOhEcSxQQjvs8ssRaWq9aqEHyxCxuc9BWoqvB
Am9iwrNpmUmlRbFwDOwtICZRbqAf799pOFo1i8WKQc/J5y1KwZCCg3GAEBv8CNQE
vMVH5ygi1fMeQPNg8oWDD+3gP1GmLGMP14kHT/aPyDAHHUMrq7nSgA8SXTC9fihO
sygULgtpiSjKgeg9cTvK9yhz7T0c2CxFgyhUnz4v6uZtQTJK2Q==
-----END CERTIFICATE-----`

func DummyProvider() (Session, error) {
	block, _ := pem.Decode([]byte(dummyPrivKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dummy private key: %v", err)
	}

	certBlock, _ := pem.Decode([]byte(dummyCert))
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	return &dummySession{
		random:     rand.Reader,
		privateKey: key,
		caCert:     caCert,
		caCertDER:  certBlock.Bytes,
	}, nil
}

type dummySession struct {
	privateKey *rsa.PrivateKey
	caCert     *x509.Certificate
	caCertDER  []byte
	random     io.Reader
	closed     atomic.Bool
}

func (d *dummySession) Read(p []byte) (n int, err error) {
	if d.closed.Load() {
		return 0, fmt.Errorf("session is closed")
	}
	return d.random.Read(p)
}

func (d *dummySession) Close() error {
	d.closed.Store(true)
	return nil
}

func (d *dummySession) Send(ctx context.Context, req request.Request) (response.Response, error) {
	switch req := req.(type) {
	case *request.Attestation:
		return d.handleAttestation(req)
	case *request.DescribePCR:
		return d.handleDescribePCR(req)
	default:
		return response.Response{}, fmt.Errorf("unsupported request type: %T", req)
	}
}

func (d *dummySession) handleAttestation(req *request.Attestation) (response.Response, error) {
	certDER, privateKey, err := d.generateCertificate()
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to generate certificate: %v", err)
	}

	pcr := make([]byte, 48)
	rawDoc := struct {
		ModuleID    string         `cbor:"module_id"`
		Timestamp   uint64         `cbor:"timestamp"`
		Digest      string         `cbor:"digest"`
		PCRs        map[int][]byte `cbor:"pcrs"`
		Certificate []byte         `cbor:"certificate"`
		CABundle    [][]byte       `cbor:"cabundle"`
		PublicKey   []byte         `cbor:"public_key"`
		UserData    []byte         `cbor:"user_data"`
		Nonce       []byte         `cbor:"nonce"`
	}{
		ModuleID:  "dummy-module",
		Timestamp: uint64(time.Now().Unix() * 1000),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: pcr,
			1: pcr,
			2: pcr,
			3: pcr,
		},
		Certificate: certDER,
		CABundle:    [][]byte{d.caCertDER},
		PublicKey:   req.PublicKey,
		UserData:    req.UserData,
		Nonce:       req.Nonce,
	}

	rawDocBytes, err := cbor.Marshal(rawDoc)
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal raw document: %v", err)
	}

	sigStructCBOR, err := cbor.Marshal([]any{"Signature1", []byte{}, []byte{}, rawDocBytes})
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal signature structure: %v", err)
	}
	hash := crypto.SHA384.New()
	if _, err := hash.Write(sigStructCBOR); err != nil {
		return response.Response{}, fmt.Errorf("failed to hash signature structure: %v", err)
	}
	digest := hash.Sum(nil)

	derSig, err := privateKey.Sign(rand.Reader, digest, crypto.SHA384)
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to sign digest: %v", err)
	}

	var esig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &esig); err != nil {
		return response.Response{}, fmt.Errorf("failed to unmarshal ASN.1 signature: %v", err)
	}

	rBytes := esig.R.FillBytes(make([]byte, 48)) // 48 bytes for P-384
	sBytes := esig.S.FillBytes(make([]byte, 48))
	sig := append(rBytes, sBytes...)

	document, err := cbor.Marshal([]any{[]byte{}, struct{}{}, rawDocBytes, sig})
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal COSE_Sign1: %v", err)
	}

	res := response.Response{
		Attestation: &response.Attestation{
			Document: document,
		},
	}
	return res, nil
}

func (d *dummySession) handleDescribePCR(req *request.DescribePCR) (response.Response, error) {
	hash := make([]byte, 48)
	res := response.Response{
		DescribePCR: &response.DescribePCR{
			Lock: true,
			Data: hash,
		},
	}
	return res, nil
}

func (d *dummySession) generateCertificate() ([]byte, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sequence"},
			CommonName:   "dummy.nitro-enclaves",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, d.caCert, &privateKey.PublicKey, d.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return certBytes, privateKey, nil
}
