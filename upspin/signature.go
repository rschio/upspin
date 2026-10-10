package upspin

import (
	"encoding/base64"
)

func ParseSignature(v string) (Signature, error) {
	sig, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return Signature(sig), nil
}

func (s Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(s)
}
