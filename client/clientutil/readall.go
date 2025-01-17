// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientutil implements common utilities shared by clients and those
// who act as clients, such as a DirServer being a client of a StoreServer.
package clientutil // import "upspin.io/client/clientutil"

import (
	"upspin.io/access"
	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/path"
	"upspin.io/upspin"
)

// ReadAll reads the entire contents of a DirEntry. The reader must have
// the necessary keys loaded in the config to unpack the cipher if the entry
// is encrypted.
func ReadAll(cfg upspin.Config, entry *upspin.DirEntry) ([]byte, error) {
	if entry.IsLink() {
		return nil, errors.E(entry.Name, errors.Invalid, "can't read a link entry")
	}
	if entry.IsIncomplete() {
		return nil, errors.E(entry.Name, errors.Permission)
	}
	if access.IsAccessFile(entry.SignedName) {
		// Access files must be written by their owners only.
		p, _ := path.Parse(entry.SignedName)
		if p.User() != entry.Writer {
			return nil, errors.E(errors.Invalid, p.User(), "writer of Access file does not match owner")
		}
	}

	unpack, err := NewBUIter(cfg, entry)
	if err != nil {
		return nil, errors.E(entry.Name, err)
	}

	var data []byte
	for cleartext, err := range unpack.All() {
		if err != nil {
			return nil, err
		}
		data = append(data, cleartext...)
	}

	return data, nil
}

// ReadLocation uses the provided Config to fetch the contents of the given
// Location, following any StoreServer.Get redirects.
func ReadLocation(cfg upspin.Config, loc upspin.Location) ([]byte, error) {
	// firstError remembers the first error we saw.
	// If we fail completely we return it.
	var firstError error
	// isError reports whether err is non-nil and remembers it if it is.
	isError := func(err error) bool {
		if err == nil {
			return false
		}
		if firstError == nil {
			firstError = err
		}
		return true
	}

	// knownLocs stores the known Locations for this block. Value is
	// ignored.
	knownLocs := make(map[upspin.Location]bool)
	// Get the data for this block.
	// where is the list of locations to examine. It is updated in the loop.
	where := []upspin.Location{loc}
	for i := 0; i < len(where); i++ { // Not range loop - where changes as we run.
		loc := where[i]
		store, err := bind.StoreServer(cfg, loc.Endpoint)
		if isError(err) {
			continue
		}
		data, _, locs, err := store.Get(loc.Reference)
		if isError(err) {
			continue // locs guaranteed to be nil.
		}
		if locs == nil && err == nil {
			return data, nil
		}
		// Add new locs to the list. Skip ones already there - they've been processed.
		for _, newLoc := range locs {
			if _, found := knownLocs[newLoc]; !found {
				where = append(where, newLoc)
				knownLocs[newLoc] = true
			}
		}
	}

	// If we arrive here, we have failed to find a block.
	if firstError != nil {
		return nil, errors.E(firstError)
	}
	return nil, errors.E(errors.IO, errors.Errorf("data for location %v not found on any store server", loc))
}
