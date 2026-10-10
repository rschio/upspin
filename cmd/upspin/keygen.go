// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// This file contains the implementation of the keygen command.

import (
	"flag"
	"fmt"
	"path/filepath"

	"upspin.io/key/keygen"
)

func (s *State) keygen(args ...string) {
	const help = `
Keygen creates a new Upspin key pair and stores the pair in local files
secret.upspinkey and public.upspinkey in the specified directory.
Existing key pairs are appended to secret2.upspinkey.
Keygen does not update the information in the key server;
use the "user -put" command for that.

New users should instead use the "signup" command to create their first key.

See the description for rotate for information about updating keys.
`
	// Keep flags in sync with signup.go. New flags here should appear
	// there as well.
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	var (
		rotate = fs.Bool("rotate", false, "back up the existing keys and replace them with new ones")
	)
	s.ParseFlags(fs, args, help, "keygen [-curve=256] [-secretseed=seed] <directory>")
	if fs.NArg() != 1 {
		usageAndExit(fs)
	}
	s.keygenCommand(fs.Arg(0), *rotate)
}

func (s *State) keygenCommand(where string, rotate bool) {
	public, private, err := s.createKeys()
	if err != nil {
		s.Exitf("creating keys: %v", err)
	}

	err = keygen.SaveKeys(where, rotate, public, private)
	if err != nil {
		s.Exitf("keys not generated: %s", err)
	}
	if rotate {
		archiveFile := filepath.Join(where, "secret2.upspinkey")
		fmt.Fprintf(s.Stderr, "Saved previous key pair to:\n\t%s\n", archiveFile)
	}

	fmt.Fprintln(s.Stderr, "Upspin private/public key pair written to:")
	fmt.Fprintf(s.Stderr, "\t%s\n", filepath.Join(where, "public.upspinkey"))
	fmt.Fprintf(s.Stderr, "\t%s\n", filepath.Join(where, "secret.upspinkey"))
	fmt.Fprintln(s.Stderr, "This key pair provides access to your Upspin identity and data.")
	if rotate {
		fmt.Fprintln(s.Stderr, "\nTo install new keys in the key server, see 'upspin rotate -help'.")
	}
	fmt.Fprintln(s.Stderr)
}

func (s *State) createKeys() (public, private string, err error) {
	return keygen.Generate()
}
