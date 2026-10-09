// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ee

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"

	"upspin.io/errors"
	"upspin.io/pack/packutil"
	"upspin.io/upspin"
)

// wrappedKey encodes a key that will decrypt and verify the ciphertext.
type wrappedKey struct {
	keyHash []byte // recipient's public key
	dkey    []byte // ciphertext symmetric decryption key
}

// packdata is a structured representation of the DirEntry's Packdata field.
type packdata struct {
	// sig is the signature with the primary owner key.
	sig upspin.Signature
	// sig2 is the signature with the previous owner key,
	// to enable smoother key rotation.
	sig2 upspin.Signature
	// wrap is the file key, encoded with a set of reader keys.
	wrap []wrappedKey
	// blockSum is a checksum of the blocks.
	blockSum []byte
}

// Marshal stores the binary-encoded version of packdata in the given slice,
// copying byte arrays to dst in the order declared in the struct definitions
// and prefixed with lengths using binary.PutVarint.
// A slice will be allocated and the pointer overwritten if *dst is too short.
func (pd *packdata) Marshal(dst *[]byte) error {
	if n := packdataLen(len(pd.wrap)); len(*dst) < n {
		*dst = make([]byte, n)
	}

	n := 0

	// sig
	n += packutil.PutBytes((*dst)[n:], pd.sig)

	// sig2
	n += packutil.PutBytes((*dst)[n:], pd.sig2)

	// wrap
	n += binary.PutVarint((*dst)[n:], int64(len(pd.wrap)))
	for _, w := range pd.wrap {
		n += packutil.PutBytes((*dst)[n:], w.keyHash)
		n += packutil.PutBytes((*dst)[n:], w.dkey)
	}

	// blockSum
	n += packutil.PutBytes((*dst)[n:], pd.blockSum)

	*dst = (*dst)[:n]
	return nil
}

// Unmarshal parses the given packdata slice and stores its contents in the
// receiver pd.
func (pd *packdata) Unmarshal(b []byte) error {
	if len(b) == 0 {
		return errors.Str("nil packdata")
	}
	n := 0

	buf := make([]byte, marshalBufLen)
	// sig
	n += packutil.GetBytes(&buf, b[n:])
	pd.sig = append([]byte(nil), buf...)

	// sig2
	n += packutil.GetBytes(&buf, b[n:])
	pd.sig2 = append([]byte(nil), buf...)

	// wrap
	nwrap64, vlen := binary.Varint(b[n:])
	n += vlen
	nwrap := int(nwrap64)
	if int64(nwrap) != nwrap64 {
		return errors.Errorf("implausible number of wrapped keys: %d\n", nwrap64)
	}
	pd.wrap = make([]wrappedKey, nwrap)
	for i := 0; i < nwrap; i++ {
		var w wrappedKey
		w.keyHash = make([]byte, sha256.Size)
		n += packutil.GetBytes(&w.keyHash, b[n:])
		n += packutil.GetBytes(&buf, b[n:])
		w.dkey = append([]byte(nil), buf...)
		pd.wrap[i] = w
	}

	// blockSum
	pd.blockSum = make([]byte, sha256.Size)
	n += packutil.GetBytes(&pd.blockSum, b[n:])
	if pd.blockSum == nil {
		return errors.Str("block checksum is required")
	}

	return nil
}

// packdataLen returns the maximum length of a packdata slice for the given
// number of wrapped keys.
func packdataLen(nwrap int) int {
	intLen := binary.MaxVarintLen64

	// nWrappedKey is the size of a single encoded wrappedKey
	nWrappedKey := intLen + sha256.Size                                      // keyHash
	nWrappedKey += intLen + aesKeyLen + gcmTagSize + mlkem.CiphertextSize768 // dkey

	n := 2 * (intLen + marshalBufLen) // for (sig, sig2)
	n += intLen                       // len(wrap)
	n += nwrap * nWrappedKey
	n += intLen + sha256.Size // blockSum
	return n
}
