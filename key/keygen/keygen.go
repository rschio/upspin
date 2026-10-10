// Copyright 2017 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package keygen provides functions for generating Upspin key pairs and
// writing them to files.
package keygen // import "upspin.io/key/keygen"

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"fmt"
	"os"
	"path/filepath"

	"upspin.io/errors"
	"upspin.io/factotum"
)

func Generate() (public, private string, err error) {
	k, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return "", "", err
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", "", err
	}
	public = string(factotum.EncodePublicKeys(k.PublicKey(), dk.EncapsulationKey()))
	private = string(factotum.EncodeSecretKeys(k, dk))
	return public, private, nil
}

// writeKeyFile writes a single key to its file, removing the file
// beforehand if necessary due to permission errors.
// If the file's parent directory does not exist, writeKeyFile creates it.
func writeKeyFile(name, key string) error {
	// Make the directory if it does not exist.
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	// Create the file.
	const create = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	fd, err := os.OpenFile(name, create, 0400)
	if os.IsPermission(err) && os.Remove(name) == nil {
		// Create may fail if file already exists and is unwritable,
		// which is how it was created.
		fd, err = os.OpenFile(name, create, 0400)
	}
	if err != nil {
		return err
	}
	// Write the key.
	_, err = fd.WriteString(key)
	if err != nil {
		fd.Close()
		return err
	}
	return fd.Close()
}

// writeKeys saves both the public and private keys to their respective files.
// writeKeys will overwrite any existing keys.
func writeKeys(where, publicKey, privateKey string) error {
	err := writeKeyFile(filepath.Join(where, "secret.upspinkey"), privateKey)
	if err != nil {
		return err
	}
	return writeKeyFile(filepath.Join(where, "public.upspinkey"), publicKey)
}

// SaveKeys writes the provided public and private keys to the given directory,
// rotating them if requested by appending the old secret to secret2.upspinkey.
// If rotate is false and there are existing keys, SaveKeys returns an error.
// If rotate is true and there are no existing keys, SaveKeys returns an error.
func SaveKeys(where string, rotate bool, newPublic, newPrivate string) error {
	var (
		publicFile  = filepath.Join(where, "public.upspinkey")
		privateFile = filepath.Join(where, "secret.upspinkey")
		archiveFile = filepath.Join(where, "secret2.upspinkey")
	)

	// Read existing key pair.
	private, err := os.ReadFile(privateFile)
	if os.IsNotExist(err) {
		// There is nothing to save. Did we expect there to be?
		if rotate {
			return errors.Errorf("cannot rotate keys: no prior keys exist in %s", where)
		}
		// We didn't expect key rotation, so just write the new keys.
		return writeKeys(where, newPublic, newPrivate)
	}
	if err != nil {
		return err
	}

	// There's an existing keypair. Did we not expect it?
	if !rotate {
		return errors.Errorf("prior keys exist in %s; rerun with rotate command to update keys", where)
	}

	public, err := os.ReadFile(publicFile)
	if err != nil {
		return err // Halt. Existing files are corrupted and need manual attention.
	}
	if string(public) == newPublic && string(private) == newPrivate {
		return nil // No need to save duplicates.
	}

	// Write old key pair to archive file.
	archive, err := os.OpenFile(archiveFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err // We don't have permission to archive old keys?
	}

	var modtime string
	info, err := os.Stat(privateFile)
	if err != nil {
		modtime = ""
	} else {
		modtime = info.ModTime().UTC().Format(" 2006-01-02 15:04:05Z")
	}
	_, err = fmt.Fprintf(archive, "# EE%s\n%s%s", modtime, public, private)
	if err != nil {
		return err
	}
	err = archive.Close()
	if err != nil {
		return err
	}

	// Write the new keys.
	return writeKeys(where, newPublic, newPrivate)
}
