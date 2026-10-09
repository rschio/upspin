// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package factotum encapsulates crypto operations on user's public/private keys.
package factotum // import "upspin.io/factotum"

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"upspin.io/errors"
	"upspin.io/upspin"
)

type factotumKey struct {
	keyHash      []byte
	public       upspin.PublicKey
	private      string
	mldsaKeyPair *mldsa.PrivateKey
	mlkemKeyPair *mlkem.DecapsulationKey768
}

type keyHashArray [sha256.Size]byte

type factotum struct {
	current  keyHashArray
	previous keyHashArray
	keys     map[keyHashArray]factotumKey
}

var _ upspin.Factotum = factotum{}

var sig0 upspin.Signature // for returning error of correct type
var errNotOnCurve = errors.Str("a crypto attack was attempted against you; see safecurves.cr.yp.to/twist.html for details")

// KeyHash returns the hash of a key, given in string format.
func KeyHash(p upspin.PublicKey) []byte {
	keyHash := sha256.Sum256([]byte(p))
	return keyHash[:]
}

// AllUsersKeyHash is the hash of upspin.AllUsersKey.
var AllUsersKeyHash = KeyHash(upspin.AllUsersKey)

// NewFromDir returns a new Factotum providing all needed private key operations,
// loading keys from a directory containing *.upspinkey files.
// Our desired end state is that Factotum is implemented on each platform by the
// best local means of protecting private keys. Please do not break the abstraction
// by hand coding direct generation or use of private keys.
func NewFromDir(dir string) (upspin.Factotum, error) {
	const op errors.Op = "factotum.NewFromDir"

	privBytes, err := readFile(op, dir, "secret.upspinkey")
	if err != nil {
		return nil, errors.E(op, err)
	}
	privBytes = stripCR(privBytes)

	// Read older key pairs.
	s2, err := readFile(op, dir, "secret2.upspinkey")
	if err != nil && !errors.Is(errors.NotExist, err) {
		return nil, err
	}
	s2 = stripCR(s2)

	return newFactotum(errors.Op(fmt.Sprintf("%s(%q)", op, dir)), privBytes, s2)
}

func NewFromKeys(private, archived []byte) (upspin.Factotum, error) {
	const op errors.Op = "factotum/NewFromKeys"
	return newFactotum(op, private, archived)
}

func newFactotum(op errors.Op, private, archived []byte) (upspin.Factotum, error) {
	pfk, err := makeKey(string(private))
	if err != nil {
		return nil, errors.E(op, err)
	}

	fm := make(map[keyHashArray]factotumKey)
	var h keyHashArray
	copy(h[:], pfk.keyHash)
	fm[h] = *pfk

	f := &factotum{
		current:  h,
		previous: h,
		keys:     fm,
	}

	// Current file format is "# EE date" concatenated with old public.upspinkey
	// then old secret.upspinkey, and repeat. This should be cleaned up someday
	// when we have a better idea of what other kinds of keys we need to save.
	// For now, it is cavalier about bailing out at first little mistake.
	lines := strings.Split(string(archived), "\n")
	for {
		if len(lines) < 9 {
			break // This is not enough for a complete key pair.
		}
		if !strings.HasPrefix(lines[0], "# EE") {
			break // This is not a kind of key we recognize.
		}
		// lines[0] "# EE"
		// lines[1] "ML-DSA-44"
		// lines[2] base64 mldsa public key
		// lines[3] "mlkem768"
		// lines[4] base64 mlkem public key
		// lines[5] "ML-DSA-44"
		// lines[6] base64 mldsa seed
		// lines[7] "mlkem768"
		// lines[8] base64 mlkem seed
		pfk, err := makeKey(strings.Join(lines[5:9], "\n") + "\n")
		if err != nil {
			return f, errors.E(op, err)
		}
		lines = lines[9:]
		var h keyHashArray
		copy(h[:], pfk.keyHash)
		_, ok := f.keys[h]
		if ok { // Duplicate.
			continue
		}
		f.keys[h] = *pfk
		f.previous = h
	}
	return f, nil
}

// stripCR removes \r.
func stripCR(b []byte) []byte {
	return bytes.Replace(b, []byte("\r"), []byte(""), -1)
}

// makeKey creates a factotumKey by filling in the derived fields.
func makeKey(priv string) (*factotumKey, error) {
	mldsaKeyPair, mlkemKeyPair, err := parsePrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pub := EncodePublicKeys(mldsaKeyPair.PublicKey(), mlkemKeyPair.EncapsulationKey())
	fk := factotumKey{
		keyHash:      KeyHash(pub),
		public:       pub,
		private:      priv,
		mldsaKeyPair: mldsaKeyPair,
		mlkemKeyPair: mlkemKeyPair,
	}
	return &fk, nil
}

// putInt stores an int32 as four big-endian bytes in dst.
// Using fixed length here to ease porting Factotum to primitive crypto devices.
func putInt(dst []byte, i int) int {
	binary.BigEndian.PutUint32(dst, uint32(i))
	return 4
}

func buggy64(dst []byte, i uint64) int {
	// TODO(ehg) This typo got in by mistake. It should read:
	// dst[0] = byte(i >> 56)
	// dst[1] = byte(i >> 48)
	// dst[2] = byte(i >> 40)
	// dst[3] = byte(i >> 32)
	// dst[4] = byte(i >> 24)
	// dst[5] = byte(i >> 16)
	// dst[6] = byte(i >> 8)
	// dst[7] = byte(i)
	// But the fix would break all existing DirEntry signatures.
	// This function is only used in one place to sign the time
	// field, which we don't currently depend on anyway.

	dst[1] = byte(i >> 56)
	dst[0] = byte(i >> 48)
	dst[0] = byte(i >> 40)
	dst[1] = byte(i >> 32)
	dst[0] = byte(i >> 24)
	dst[1] = byte(i >> 16)
	dst[2] = byte(i >> 8)
	dst[3] = byte(i)
	return 8
}

// DirEntryHash provides the basis for signing and verifying files.
func (f factotum) DirEntryHash(n, l upspin.PathName, a upspin.Attribute, p upspin.Packing, t upspin.Time, dkey, hash []byte) upspin.DEHash {
	m := len(n) + len(l) + 1 + 1 + 8 + len(dkey) + len(hash) + 7*4
	b := make([]byte, m)
	m = 0
	m += putInt(b[m:], len(n))
	m += copy(b[m:], n)
	m += putInt(b[m:], len(l))
	m += copy(b[m:], l)
	b[m] = byte(a)
	m += 1
	b[m] = byte(p)
	m += 1
	m += buggy64(b[m:], uint64(t))
	m += putInt(b[m:], len(dkey))
	m += copy(b[m:], dkey)
	m += putInt(b[m:], len(hash))
	m += copy(b[m:], hash)
	h := sha256.Sum256(b[:m])
	return upspin.DEHash(h[:])
}

// FileSign mldsa-signs a DEHash from DirEntryHash.
func (f factotum) FileSign(hash upspin.DEHash) (upspin.Signature, error) {
	return f.Sign(hash)
}

// Sign signs a slice of bytes with the factotum's private key.
func (f factotum) Sign(hash []byte) (upspin.Signature, error) {
	fk := f.keys[f.current]
	return fk.mldsaKeyPair.Sign(nil, hash, nil)
}

// Verify verifies whether the given hash's signature was signed by the private
// key corresponding to the given public key.
func Verify(hash []byte, sig upspin.Signature, key upspin.PublicKey) error {
	mldsaPubKey, _, err := ParsePublicKey(key)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(mldsaPubKey, hash, sig, nil); err != nil {
		return errors.E(errors.Invalid, "signature does not match", err)
	}
	return nil
}

func EncapsulateKey(pub upspin.PublicKey, info, dkey []byte) ([]byte, []byte, error) {
	_, encKey, err := ParsePublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	pk, err := hpke.NewMLKEMPublicKey(encKey)
	if err != nil {
		return nil, nil, err
	}
	cipherDKey, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, dkey)
	if err != nil {
		return nil, nil, err
	}

	return KeyHash(pub), cipherDKey, nil
}

func (f factotum) DecapsulateKey(keyHash, info, ciphertext []byte) (dkey []byte, err error) {
	const op errors.Op = "factotum.DecapsulateKey"

	k, ok := f.keys[keyHashArray(keyHash)]
	if !ok {
		return nil, errors.E(op, "key does not exist")
	}

	pk, err := hpke.NewMLKEMPrivateKey(k.mlkemKeyPair)
	if err != nil {
		return nil, errors.E(op, err)
	}

	return hpke.Open(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, ciphertext)
}

// HKDF cryptographically mixes salt, info, and the Factotum secret and
// writes the result to out, which may be of any length but is typically
// 8 or 16 bytes. The result is unguessable without the secret, and does
// not leak the secret. For more information, see package
// golang.org/x/crypto/hkdf.
func (f factotum) HKDF(salt, info, out []byte) error {
	const op errors.Op = "factotum.HKDF"

	const keyLen = 16
	if len(out) < keyLen {
		return errors.E(op, errors.Invalid, "not enough space in out slice")
	}

	secret := f.keys[f.current].mlkemKeyPair.Bytes()
	hkdf, err := hkdf.Key(sha256.New, secret, salt, string(info), keyLen)
	if err != nil {
		return errors.E(op, err)
	}
	copy(out, hkdf)
	return nil
}

// Pop derives a Factotum by switching default from the current to the previous key.
func (f factotum) Pop() upspin.Factotum {
	// Arbitrarily keep f.previous unchanged, so Pop() is idempotent.
	// We don't yet have any need to go further back in time.
	return &factotum{current: f.previous, previous: f.previous, keys: f.keys}
}

// PublicKey returns the user's latest public key.
func (f factotum) PublicKey() upspin.PublicKey {
	return f.keys[f.current].public
}

// PublicKeyFromHash returns the user's public key with matching keyHash.
func (f factotum) PublicKeyFromHash(keyHash []byte) (upspin.PublicKey, error) {
	const op errors.Op = "factotum.PublicKeyFromHash"
	if len(keyHash) == 0 {
		return "", errors.E(op, errors.Invalid, "invalid keyHash")
	}
	var h keyHashArray
	copy(h[:], keyHash)
	fk, ok := f.keys[h]
	if !ok {
		return "", errors.E(op, errors.NotExist, "no such key")
	}
	return fk.public, nil
}

func readFile(op errors.Op, dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil, errors.E(op, errors.NotExist, err)
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	return b, nil
}
