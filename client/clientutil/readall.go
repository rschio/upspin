// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientutil implements common utilities shared by clients and those
// who act as clients, such as a DirServer being a client of a StoreServer.
package clientutil // import "upspin.io/client/clientutil"

import (
	"context"
	"iter"
	"sync"

	"upspin.io/access"
	"upspin.io/bind"
	"upspin.io/errors"
	"upspin.io/pack"
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

	return readAll(cfg, entry)
}

// BlockIterClear iters blocks[begin:end] returning the blocks unpacked,
// the returned is slice is only valid until the next iteration.
func BlockIterClear(cfg upspin.Config, bu upspin.BlockUnpacker, begin, end int) iter.Seq2[[]byte, error] {
	concurrency := 32
	ciphers := make(chan nCipher)

	// Used to stop producer when this function returns, caused by an error.
	ctx, cancel := context.WithCancel(context.Background())

	// Producer.
	go func() {
		sema := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		defer func() {
			wg.Wait()
			close(ciphers)
		}()

		block, ok := bu.SeekBlock(begin)
		if !ok { // EOF.
			return
		}

		for n := begin; n < end && ctx.Err() == nil; n++ {
			sema <- struct{}{}
			wg.Add(1)

			go func(block upspin.DirBlock) {
				defer func() { <-sema }()
				defer wg.Done()

				var result nCipher
				cipher, err := ReadLocation(cfg, block.Location)
				if err != nil {
					result = nCipher{BlockNumber: n, Cipher: nil, Err: errors.E(err)}
				} else {
					result = nCipher{BlockNumber: n, Cipher: cipher}
				}

				select {
				case ciphers <- result:
				case <-ctx.Done():
				}
			}(block)

			block, ok = bu.NextBlock()
			if !ok { // EOF.
				return
			}
		}
	}()

	return func(yield func([]byte, error) bool) {
		defer cancel()

		window := newSlidingWindow(concurrency)
		pos := begin
		buf := new(lazyBuffer)

		for in := range ciphers {
			// Got a block that should be unpacked in the future.
			if in.BlockNumber != pos {
				window.append(in)
				// Check if there is a block to be unpacked now.
				var found bool
				in, found = window.pop(pos)
				if !found {
					continue
				}
			}
			if in.Err != nil {
				if !yield(nil, in.Err) {
					return
				}
			}

			cleartext := buf.Bytes(len(in.Cipher))
			err := bu.UnpackBlock(cleartext, in.Cipher, in.BlockNumber)
			if !yield(cleartext, err) {
				return
			}
			pos++
		}
		for window.len() > 0 {
			in, _ := window.pop(pos) // Always found.
			if in.Err != nil {
				if !yield(nil, in.Err) {
					return
				}
			}

			cleartext := buf.Bytes(len(in.Cipher))
			err := bu.UnpackBlock(cleartext, in.Cipher, in.BlockNumber)
			if !yield(cleartext, err) {
				return
			}
			pos++
		}
	}
}

func readAll(cfg upspin.Config, entry *upspin.DirEntry) ([]byte, error) {
	packer := pack.Lookup(entry.Packing)
	if packer == nil {
		return nil, errors.E(entry.Name, errors.Errorf("unrecognized Packing %d", entry.Packing))
	}
	bu, err := packer.Unpack(cfg, entry)
	if err != nil {
		return nil, errors.E(entry.Name, err) // Showstopper.
	}

	var data []byte
	for cleartext, err := range BlockIterClear(cfg, bu, 0, len(entry.Blocks)) {
		if err != nil {
			return nil, err
		}
		data = append(data, cleartext...)
	}

	return data, nil
}

// Copied from lazybuffer.

// lazyBuffer is a []byte that is lazily (re-)allocated when its
// Bytes method is called.
type lazyBuffer []byte

// Bytes returns a []byte that has length n. It re-uses the underlying
// LazyBuffer []byte if it is at least n bytes in length.
func (b *lazyBuffer) Bytes(n int) []byte {
	if *b == nil || len(*b) < n {
		*b = make([]byte, n)
	}
	return (*b)[:n]
}

type slidingWindow struct {
	window []nCipher
}

func newSlidingWindow(cap int) *slidingWindow {
	return &slidingWindow{window: make([]nCipher, 0, cap)}
}

func (w *slidingWindow) len() int {
	return len(w.window)
}

func (w *slidingWindow) append(nc nCipher) {
	w.window = append(w.window, nc)
}

func (w *slidingWindow) pop(blockNumber int) (nc nCipher, found bool) {
	for i, val := range w.window {
		if val.BlockNumber == blockNumber {
			last := len(w.window) - 1
			w.window[last], w.window[i] = w.window[i], w.window[last]
			w.window = w.window[:len(w.window)-1]
			return val, true
		}
	}

	return nCipher{}, false
}

type nCipher struct {
	BlockNumber int
	Cipher      []byte
	Err         error
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
