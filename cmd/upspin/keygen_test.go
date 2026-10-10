// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/key/keygen"
)

func TestSaveKeygen(t *testing.T) {
	s := newState("test")
	public0, private0, err := s.createKeys()
	if err != nil {
		t.Fatalf("creating keys: %v", err)
	}

	// Write them to a file.
	dir, err := os.MkdirTemp("", "keygen")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	err = keygen.SaveKeys(dir, false, public0, private0)
	if err != nil {
		t.Fatalf("writing keys: %v", err)
	}

	// Read them back.
	data, err := os.ReadFile(filepath.Join(dir, "public.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != public0 {
		t.Fatalf("reading public key: got %q; want %q", data, public0)
	}
	data, err = os.ReadFile(filepath.Join(dir, "secret.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(private0) + "\n"
	if got := string(data); got != want {
		t.Fatalf("reading secret key: got %q; want %q", got, want)
	}

	// Generate again.
	public, private, err := s.createKeys()
	if err != nil {
		t.Fatalf("creating keys: %v", err)
	}

	// Update and rotate keys.
	err = keygen.SaveKeys(dir, true, public, private)
	if err != nil {
		t.Fatalf("saving keys: %v", err)
	}

	// Read them back.
	data, err = os.ReadFile(filepath.Join(dir, "public.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != public {
		t.Fatalf("reading public key: got %q; want %q", data, public)
	}
	data, err = os.ReadFile(filepath.Join(dir, "secret.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	want = strings.TrimSpace(private) + "\n"
	if got := string(data); got != want {
		t.Fatalf("reading secret key: got %q; want %q", got, want)
	}

	// Now check the archive.
	data, err = os.ReadFile(filepath.Join(dir, "secret2.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.IndexByte(data, '\n')
	if i >= 0 {
		data = data[i+1:] // Strip "# EE modtime".
	}
	if string(data) != public0+private0 {
		t.Fatalf("reading archive key: got\n%s\n\twant\n%s", data, public0+private0)
	}
}
