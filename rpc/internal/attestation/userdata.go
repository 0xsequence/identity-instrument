package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
)

func generateUserData(r *http.Request, resBody []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write([]byte(r.Method + " " + r.URL.Path + "\n"))

	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		hasher.Write(reqBody)
	}
	hasher.Write([]byte("\n"))
	hasher.Write(resBody)
	hash := hasher.Sum(nil)

	userData := "Sequence/1:" + base64.StdEncoding.EncodeToString(hash)
	return []byte(userData), nil
}
