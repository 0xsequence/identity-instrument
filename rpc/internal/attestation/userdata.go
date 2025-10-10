package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

const (
	_UserDataPrefix  = "Sequence"
	_UserDataVersion = 1
)

type userData struct {
	Prefix  string
	Version int
	Hash    []byte
}

func (u *userData) String() string {
	return fmt.Sprintf("%s/%d:%s", u.Prefix, u.Version, base64.StdEncoding.EncodeToString(u.Hash))
}

func generateUserData(r *http.Request, resBody []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write([]byte(r.Method + " " + r.URL.Path + "\n"))

	var reqBody []byte
	var err error
	if r.Body != nil {
		reqBody, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		hasher.Write(reqBody)
	}
	hasher.Write([]byte("\n"))
	hasher.Write(resBody)
	hash := hasher.Sum(nil)

	userData := &userData{
		Prefix:  _UserDataPrefix,
		Version: _UserDataVersion,
		Hash:    hash,
	}
	return []byte(userData.String()), nil
}
