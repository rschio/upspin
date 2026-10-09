package factotum

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"strings"

	"upspin.io/errors"
	"upspin.io/upspin"
)

func parsePrivateKey(privateKey string) (*mldsa.PrivateKey, *mlkem.DecapsulationKey768, error) {
	const op errors.Op = "factotum.parsePrivateKeyPQ"

	params, seed, decapsulationSeed, err := parseKeyPQ(op, privateKey)
	if err != nil {
		return nil, nil, errors.E(op, err)
	}
	sigKey, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, nil, errors.E(op, err)
	}

	decKey, err := mlkem.NewDecapsulationKey768(decapsulationSeed)
	if err != nil {
		return nil, nil, errors.E(op, err)
	}

	return sigKey, decKey, nil
}

func ParsePublicKey(public upspin.PublicKey) (*mldsa.PublicKey, *mlkem.EncapsulationKey768, error) {
	const op errors.Op = "factotum.ParsePublicKeyPQ"

	params, sigKeyBytes, encapsulationKey, err := parseKeyPQ(op, string(public))
	if err != nil {
		return nil, nil, errors.E(op, err)
	}
	sigKey, err := mldsa.NewPublicKey(params, sigKeyBytes)
	if err != nil {
		return nil, nil, errors.E(op, err)
	}

	encKey, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, errors.E(op, err)
	}

	return sigKey, encKey, nil
}

func parseKeyPQ(op errors.Op, key string) (params mldsa.Parameters, sigKey, mlkemKey []byte, err error) {
	fields := strings.Split(key, "\n")
	if len(fields) != 5 {
		return mldsa.Parameters{}, nil, nil, errors.E(op, errors.Invalid,
			errors.Errorf("expected keytype, base64 RawURL encoded and a new line; got %d %v",
				len(fields), fields))
	}
	keyType := fields[0]
	base64SigKey := fields[1]

	params, sigKey, err = parseSignatureKey(op, keyType, base64SigKey)
	if err != nil {
		return mldsa.Parameters{}, nil, nil, err
	}

	mlkemKeyType := fields[2]
	base64Mlkem := fields[3]
	mlkemKey, err = parseMlkemKey(op, mlkemKeyType, base64Mlkem)
	if err != nil {
		return mldsa.Parameters{}, nil, nil, err
	}

	return params, sigKey, mlkemKey, nil
}

func parseMlkemKey(op errors.Op, _, base64Key string) ([]byte, error) {
	keyBytes, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, errors.E(op, errors.Invalid, "failed to decode key bytes")
	}
	return keyBytes, nil
}

func parseSignatureKey(op errors.Op, keyType, base64Key string) (mldsa.Parameters, []byte, error) {
	var params mldsa.Parameters
	switch keyType {
	case mldsa.MLDSA44().String():
		params = mldsa.MLDSA44()
	case mldsa.MLDSA65().String():
		params = mldsa.MLDSA65()
	case mldsa.MLDSA87().String():
		params = mldsa.MLDSA87()
	default:
		return mldsa.Parameters{}, nil, errors.E(op, errors.Invalid, errors.Errorf("unknown key type: %q", keyType))
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(base64Key)
	if err != nil {
		return mldsa.Parameters{}, nil, errors.E(op, errors.Invalid, "failed to decode key bytes")
	}

	return params, keyBytes, nil
}

func EncodeSecretKeys(sigKey *mldsa.PrivateKey, decapKey *mlkem.DecapsulationKey768) []byte {
	k0 := encodePrivateKey(sigKey)
	k1 := encodeDecapsulationKey(decapKey)
	out := make([]byte, len(k0)+len(k1))
	copy(out, k0)
	copy(out[len(k0):], k1)
	return out
}

func EncodePublicKeys(sigKey *mldsa.PublicKey, encapKey *mlkem.EncapsulationKey768) upspin.PublicKey {
	k0 := encodePublicKey(sigKey)
	k1 := encodeEncapsulationKey(encapKey)
	out := make([]byte, len(k0)+len(k1))
	copy(out, k0)
	copy(out[len(k0):], k1)
	return upspin.PublicKey(out)
}

func encodePrivateKey(k *mldsa.PrivateKey) []byte {
	params := k.PublicKey().Parameters().String()
	b64Bytes := base64.RawURLEncoding.EncodeToString(k.Bytes())
	s := fmt.Sprintf("%s\n%s\n", params, b64Bytes)
	return []byte(s)
}

func encodePublicKey(k *mldsa.PublicKey) []byte {
	params := k.Parameters().String()
	b64Bytes := base64.RawURLEncoding.EncodeToString(k.Bytes())
	s := fmt.Sprintf("%s\n%s\n", params, b64Bytes)
	return []byte(s)
}

func encodeDecapsulationKey(k *mlkem.DecapsulationKey768) []byte {
	params := "mlkem768"
	b64Bytes := base64.RawURLEncoding.EncodeToString(k.Bytes())
	s := fmt.Sprintf("%s\n%s\n", params, b64Bytes)
	return []byte(s)
}

func encodeEncapsulationKey(k *mlkem.EncapsulationKey768) []byte {
	params := "mlkem768"
	b64Bytes := base64.RawURLEncoding.EncodeToString(k.Bytes())
	s := fmt.Sprintf("%s\n%s\n", params, b64Bytes)
	return []byte(s)
}
